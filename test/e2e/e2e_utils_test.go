package e2e_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/kubev2v/migration-planner/api/v1alpha1"
	"github.com/kubev2v/migration-planner/internal/cli"
	. "github.com/onsi/gomega"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Create a source in the DB using the API
func CreateSource(name string) *v1alpha1.Source {
	source, err := svc.CreateSource(name)
	Expect(err).To(BeNil())
	Expect(source).NotTo(BeNil())
	return source
}

// Create VM with the UUID of the source created
func CreateAgent(configPath string, idForTest string, uuid uuid.UUID, vmName string) (PlannerAgent, string) {
	agent, err := NewPlannerAgent(configPath, uuid, vmName, idForTest)
	Expect(err).To(BeNil(), "Failed to create PlannerAgent")
	err = agent.Run()
	Expect(err).To(BeNil(), "Failed to run PlannerAgent")
	var agentIP string
	Eventually(func() string {
		agentIP, err = agent.GetIp()
		if err != nil {
			return ""
		}
		return agentIP
	}, "4m").ShouldNot(BeEmpty())
	Expect(agentIP).ToNot(BeEmpty())
	Eventually(func() bool {
		return agent.IsServiceRunning(agentIP, "planner-agent")
	}, "4m").Should(BeTrue())
	return agent, agentIP
}

// Login to VSphere and put the credentials
func LoginToVsphere(agent PlannerAgent, address string, port string, username string, password string, expectedStatusCode int) {
	res, err := agent.Login(fmt.Sprintf("https://%s:%s/sdk", address, port), username, password)
	Expect(err).To(BeNil())
	Expect(res.StatusCode).To(Equal(expectedStatusCode))
}

// check that source is up to date eventually
func WaitForAgentToBeUpToDate(uuid uuid.UUID) {
	Eventually(func() bool {
		source, err := svc.GetSource(uuid)
		if err != nil {
			return false
		}
		return source.Agent.Status == v1alpha1.AgentStatusUpToDate
	}, "6m").Should(BeTrue())
}

// Wait for the service to return correct credential url for a source by UUID
func WaitForValidCredentialURL(uuid uuid.UUID, agentIP string) {
	Eventually(func() string {
		s, err := svc.GetSource(uuid)
		if err != nil {
			return ""
		}
		if s.Agent == nil {
			return ""
		}
		if s.Agent.CredentialUrl != "N/A" && s.Agent.CredentialUrl != "" {
			return s.Agent.CredentialUrl
		}

		return ""
	}, "4m").Should(Equal(fmt.Sprintf("https://%s:3333", agentIP)))
}

func ValidateTar(file *os.File) error {
	_, _ = file.Seek(0, 0)
	tarReader := tar.NewReader(file)
	containsOvf := false
	containsVmdk := false
	containsIso := false
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeReg:
			if strings.HasSuffix(header.Name, ".vmdk") {
				containsVmdk = true
			}
			if strings.HasSuffix(header.Name, ".ovf") {
				// Validate OVF file
				ovfContent, err := io.ReadAll(tarReader)
				if err != nil {
					return fmt.Errorf("failed to read OVF file: %w", err)
				}

				// Basic validation: check if the content contains essential OVF elements
				if !strings.Contains(string(ovfContent), "<Envelope") ||
					!strings.Contains(string(ovfContent), "<VirtualSystem") {
					return fmt.Errorf("invalid OVF file: missing essential elements")
				}
				containsOvf = true
			}
			if strings.HasSuffix(header.Name, ".iso") {
				containsIso = true
			}
		}
	}
	if !containsOvf {
		return fmt.Errorf("error ova image don't contain file with ovf suffix")
	}
	if !containsVmdk {
		return fmt.Errorf("error ova image don't contain file with vmdk suffix")
	}
	if !containsIso {
		return fmt.Errorf("error ova image don't contain file with iso suffix")
	}

	return nil
}

func Untar(file *os.File, destFile string, fileName string) error {
	_, _ = file.Seek(0, 0)
	tarReader := tar.NewReader(file)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeReg:
			if header.Name == fileName {
				outFile, err := os.Create(destFile)
				if err != nil {
					return fmt.Errorf("failed to create file: %w", err)
				}
				defer outFile.Close()

				if _, err := io.Copy(outFile, tarReader); err != nil {
					return fmt.Errorf("failed to write file: %w", err)
				}
				return nil
			}
		}
	}

	return fmt.Errorf("file %s not found", fileName)
}

func (p *plannerAgentLibvirt) CreateVm() error {
	// Read VM XML definition from file
	vmXMLBytes, err := os.ReadFile(p.getConfigXmlVMPath())
	if err != nil {
		return fmt.Errorf("failed to read VM XML file: %v", err)
	}
	domain, err := p.con.DomainDefineXML(string(vmXMLBytes))
	if err != nil {
		return fmt.Errorf("failed to define domain: %v", err)
	}
	defer func() {
		_ = domain.Free()
	}()

	// Start the domain
	if err := domain.Create(); err != nil {
		return fmt.Errorf("failed to create domain: %v", err)
	}
	return nil
}

func RunSSHCommand(ip string, command string) (string, error) {
	sshCmd := exec.Command("sshpass", "-p", "123456", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", fmt.Sprintf("core@%s", ip), command)

	var stdout, stderr bytes.Buffer
	sshCmd.Stdout = &stdout
	sshCmd.Stderr = &stderr

	if err := sshCmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("command failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	return stdout.String(), nil
}

func RunLocalCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("command failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	return stdout.String(), nil
}

func getToken(username string, organization string) (string, error) {
	privateKeyString, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("error, unable to read the private key: %v", err)
	}

	privateKey, err := cli.ParsePrivateKey(string(privateKeyString))
	if err != nil {
		return "", fmt.Errorf("error with parsing the private key: %v", err)
	}

	token, err := cli.GenerateToken(username, organization, privateKey)
	if err != nil {
		return "", fmt.Errorf("error, unable to generate token: %v", err)
	}

	return token, nil
}

func (p *plannerAgentLibvirt) DisableServiceConnection() error {
	isoPath := p.IsoFilePath()
	ignitionOutputPath := filepath.Join(defaultBasePath, "ignition.ign")

	// Retrieve the content of the original Ignition file
	ignitionData, err := fetchIgnition(isoPath)
	if err != nil {
		return fmt.Errorf("unable to extract the ignition file from %s: %v\n", isoPath, err)
	}

	// Extract the contents of config.yaml
	configFilePath := "/home/core/.migration-planner/config/config.yaml"
	encodedConfigData, err := fetchEncodedConfig(ignitionData, configFilePath)
	if err != nil {
		return fmt.Errorf("unable to extract config.yaml encoded value from ignition file at %s: %v\n", configFilePath, err)
	}

	// Replace the service address IP with localhost to make it unreachable
	updatedConfigBase64, err := modifyServerURL(encodedConfigData, systemIP, "127.0.0.1:7443")
	if err != nil {
		return fmt.Errorf("unable to modify the config.yaml with new server address: %v", err)
	}

	// Export a new Ignition file with the updated configuration
	if _, err = RunLocalCommand(fmt.Sprintf(
		"echo '%s' |"+
			" jq '(.storage.files[] |"+
			" select(.path == \"%s\") |"+
			" .contents.source) = \"data:;base64,%s\"' > %s",
		ignitionData, configFilePath, updatedConfigBase64, ignitionOutputPath)); err != nil {
		return fmt.Errorf("unable to create new ignition file: %v\n", err)
	}
	defer os.Remove(ignitionOutputPath)

	// Embed the updated Ignition file into the ISO
	if err := overrideIsoIgnition(ignitionOutputPath, isoPath); err != nil {
		return fmt.Errorf("unable to embed the updated ignition into ISO: %v\n", err)
	}

	return nil
}

func fetchIgnition(isoPath string) (string, error) {
	output, err := RunLocalCommand(fmt.Sprintf("coreos-installer iso ignition show %s", isoPath))
	if err != nil {
		return "", err
	}
	return output, nil
}

func fetchEncodedConfig(ignitionData string, configPath string) (string, error) {
	output, err := RunLocalCommand(
		fmt.Sprintf("echo '%s' | "+
			"jq -r '.storage.files[] | "+
			"select(.path == \"%s\") | "+
			".contents.source'",
			ignitionData, configPath))

	if err != nil {
		return "", err
	}

	return output, nil
}

// Function to decode, modify, compress, and return the updated base64 string
func modifyServerURL(encodedData string, oldServer, newServer string) (string, error) {
	// Remove the "data:;base64," prefix
	encodedData = strings.TrimPrefix(encodedData, "data:;base64,")

	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", fmt.Errorf("error decoding base64: %v", err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(decodedData))
	if err != nil {
		return "", fmt.Errorf("error decompressing gzip: %v", err)
	}
	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("error reading decompressed data: %v", err)
	}

	modifiedData := strings.Replace(string(decompressedData), oldServer, newServer, -1)

	var compressedData bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedData)
	_, err = gzipWriter.Write([]byte(modifiedData))
	if err != nil {
		return "", fmt.Errorf("error compressing modified data: %v", err)
	}
	gzipWriter.Close()

	encodedModifiedData := base64.StdEncoding.EncodeToString(compressedData.Bytes())

	return encodedModifiedData, nil
}

func overrideIsoIgnition(ignitionFilePath string, isoPath string) error {
	if _, err := RunLocalCommand(
		fmt.Sprintf("coreos-installer iso ignition embed -fi %s %s",
			ignitionFilePath, isoPath)); err != nil {
		return err
	}

	return nil
}
