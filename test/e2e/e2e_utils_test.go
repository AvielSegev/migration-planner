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
	}, "3m").ShouldNot(BeEmpty())
	Expect(agentIP).ToNot(BeEmpty())
	Eventually(func() bool {
		return agent.IsServiceRunning(agentIP, "planner-agent")
	}, "3m").Should(BeTrue())
	return agent, agentIP
}

// Login to VSphere and put the credentials
func LoginToVsphere(username string, password string, expectedStatusCode int) {
	res, err := agent.Login(fmt.Sprintf("https://%s:8989/sdk", systemIP), username, password)
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
	}, "3m").Should(BeTrue())
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
	}, "3m").Should(Equal(fmt.Sprintf("https://%s:3333", agentIP)))
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
			return fmt.Errorf("error reading tar header: %w", err)
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
					return fmt.Errorf("error reading OVF file: %w", err)
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
			return fmt.Errorf("error reading tar header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeReg:
			if header.Name == fileName {
				outFile, err := os.Create(destFile)
				if err != nil {
					return fmt.Errorf("error creating file: %w", err)
				}
				defer outFile.Close()

				if _, err := io.Copy(outFile, tarReader); err != nil {
					return fmt.Errorf("error writing file: %w", err)
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

func RunCommand(ip string, command string) (string, error) {
	sshCmd := exec.Command("sshpass", "-p", "123456", "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", fmt.Sprintf("core@%s", ip), command)

	var stdout, stderr bytes.Buffer
	sshCmd.Stdout = &stdout
	sshCmd.Stderr = &stderr

	if err := sshCmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("command failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	return stdout.String(), nil
}

func getToken(username string, organization string) error {
	if jwtToken == "" {
		privateKeyString, err := os.ReadFile(defaultPrivateKeyPath)
		if err != nil {
			return fmt.Errorf("error, unable to read the private key: %v", err)
		}

		privateKey, err := cli.ParsePrivateKey(string(privateKeyString))
		if err != nil {
			return fmt.Errorf("error with parsing the private key: %v", err)
		}

		token, err := cli.GenerateToken(username, organization, privateKey)
		if err != nil {
			return fmt.Errorf("error, unable to generate token: %v", err)
		}

		jwtToken = token
	}
	return nil
}

func DisableServiceConnection() error {
	isoPath := filepath.Join(defaultBasePath, "agent.iso")
	exportedIgnitionPath := filepath.Join(defaultBasePath, "ignition.ign")

	// Get the content of the original ignition file
	ignitionData, err := fetchIgnition(isoPath)
	if err != nil {
		return fmt.Errorf("unable to extract the ignition file: %v\n", err)
	}

	// Extracting the config.yaml content
	configPath := "/home/core/.migration-planner/config/config.yaml"
	encodedConfig, err := fetchEncodedConfig(ignitionData, configPath)
	if err != nil {
		return fmt.Errorf("unable to extract config.yaml original encoded value: %v\n", err)
	}

	// Replacing the service address ip to localhost in order to make it unreachable
	newConfigBase64Encoded, err := modifyServerURL(encodedConfig, systemIP, "127.0.0.1:7443")
	if err != nil {
		return fmt.Errorf("unable to get the Base64 new config.yaml content: %v", err)
	}

	// Export new ignition file with updated config content
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("echo '%s' |"+
			" jq '(.storage.files[] |"+
			" select(.path == \"%s\") |"+
			" .contents.source) = \"data:;base64,%s\"' > %s",
			ignitionData, configPath, newConfigBase64Encoded, exportedIgnitionPath))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to create new igniton file: %v\n", err)
	}

	////------------------------------------------
	//
	//isoExtractionFolder := filepath.Join(defaultBasePath, "exported")
	//err = os.MkdirAll(isoExtractionFolder, 0755)
	//if err != nil {
	//	return fmt.Errorf("unable to create export directory: %v", err)
	//}
	//
	////defer os.RemoveAll(isoExtractionFolder)
	//
	//err = isoeditor.Extract(isoPath, isoExtractionFolder)
	//if err != nil {
	//	return fmt.Errorf("unable to mount iso to folder: %v\n", err)
	//}
	//
	//content, err := os.ReadFile(exportedIgnitionPath)
	//if err != nil {
	//	return fmt.Errorf("unable to load new ignition file: %v\n", err)
	//}
	//data, err := isoeditor.NewIgnitionImageReader(isoPath, &isoeditor.IgnitionContent{Config: content})
	//defer data[0].Data.Close()
	//
	//file, err := os.OpenFile(filepath.Join(isoExtractionFolder, data[0].Filename), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	//if err != nil {
	//	return fmt.Errorf("failed to open file: %v", err)
	//}
	//defer file.Close()
	//
	//_, err = io.Copy(file, data[0].Data)
	//if err != nil {
	//	return fmt.Errorf("failed to write data: %v", err)
	//}
	//
	//// Remove the old ISO
	//if _, err := os.Stat(isoPath); err == nil {
	//	if err := os.Remove(isoPath); err != nil {
	//		return fmt.Errorf("error deleting ignition file: %v", err)
	//	}
	//}
	//
	//err = isoeditor.Create(isoPath, isoExtractionFolder, "")
	//if err != nil {
	//	return fmt.Errorf("failed to create new iso file: %v", err)
	//}

	// Embed the ignition
	if err := overrideIsoIgnition(exportedIgnitionPath, isoPath); err != nil {
		return fmt.Errorf("unable to embed the ignition: %v\n", err)
	}

	//------------------------------------------

	// Remove the ignition file
	if _, err := os.Stat(exportedIgnitionPath); err == nil {
		if err := os.Remove(exportedIgnitionPath); err != nil {
			return fmt.Errorf("error deleting ignition file: %v", err)
		}
	}

	return nil
}

func fetchIgnition(isoPath string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("bash", "-c", fmt.Sprintf("coreos-installer iso ignition show %s", isoPath))

	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func fetchEncodedConfig(ignitionData string, configPath string) (string, error) {
	var buf bytes.Buffer

	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("echo '%s' | jq -r '.storage.files[] | select(.path == \"%s\") | .contents.source'",
			ignitionData, configPath))

	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return buf.String(), nil
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
	// Embed the new ignition to ISO
	cmd := exec.Command("bash", "-c", fmt.Sprintf("coreos-installer iso ignition embed -fi %s %s",
		ignitionFilePath, isoPath))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
