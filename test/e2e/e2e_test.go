package e2e_test

import (
	"fmt"
	"github.com/kubev2v/migration-planner/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"net/http"
	"os"
	"time"
)

const (
	Vsphere1Port string = "8989"
	Vsphere2Port string = "8990"
)

var (
	systemIP = os.Getenv("PLANNER_IP")
)

var testOptions = struct {
	downloadImageByUrl      bool
	disconnectedEnvironment bool
}{}

var _ = BeforeSuite(func() {
	// Create a custom development logger configuration
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.CallerKey = ""
	config.EncoderConfig.MessageKey = "msg"

	logger, _ := config.Build()
	if logger != nil {
		zap.ReplaceGlobals(logger) // Replace global logger with the custom one
	}

	// Log a test message
	zap.S().Info("Logger initialized")
})

var _ = Describe("e2e", func() {
	var (
		svc       PlannerService
		agent     PlannerAgent
		agentApi  PlannerAgentAPI
		agentIP   string
		err       error
		source    *v1alpha1.Source
		startTime time.Time
	)

	BeforeEach(func() {
		startTime = time.Now()
		testOptions.downloadImageByUrl = false
		testOptions.disconnectedEnvironment = false

		svc, err = NewPlannerService(defaultConfigPath)
		Expect(err).To(BeNil(), "Failed to create PlannerService")

		source, err = svc.CreateSource("source")
		Expect(err).To(BeNil())
		Expect(source).NotTo(BeNil())

		agent, err = CreateAgent(defaultConfigPath, defaultAgentTestID, source.Id, vmName)
		Expect(err).To(BeNil())

		zap.S().Info("Wait for agent IP...")
		Eventually(func() error {
			return FindAgentIp(agent, &agentIP)
		}, "4m", "2s").Should(BeNil())
		zap.S().Infof("Agent ip is: %s", agentIP)

		zap.S().Info("Wait for planner-agent to be running...")
		Eventually(func() bool {
			return IsPlannerAgentRunning(agent, agentIP)
		}, "4m", "2s").Should(BeTrue())
		zap.S().Info("Planner-agent is running")

		agentApi, err = agent.AgentApi()
		Expect(err).To(BeNil(), "Failed to create agent localApi")

		Eventually(func() string {
			return CredentialURL(svc, source.Id)
		}, "4m", "2s").
			Should(Equal(fmt.Sprintf("https://%s:3333", agentIP)))
		zap.S().Info("Setup complete for test.\n")
	})

	AfterEach(func() {
		zap.S().Info("Cleaning up after test...")
		err = svc.RemoveSources()
		Expect(err).To(BeNil(), "Failed to remove sources from DB")
		err = agent.Remove()
		Expect(err).To(BeNil(), "Failed to remove vm and iso")
		zap.S().Infof("Spec took %s\n", time.Since(startTime))
	})

	AfterFailed(func() {
		agent.DumpLogs(agentIP)
	})

	Context("Check Vcenter login behavior", func() {
		It("fails to authenticate with invalid vSphere credentials. "+
			"should successfully login with valid credentials", func() {
			res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"", "pass")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusBadRequest))
			zap.S().Info("Empty User. Successfully returned http status: BadRequest.")

			res, err = agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"user", "")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusBadRequest))
			zap.S().Info("Empty Password. Successfully returned http status: BadRequest.")

			res, err = agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"invalid", "cred")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusUnauthorized))
			zap.S().Info("Invalid credentials. Successfully returned http status: Unauthorized.")

			res, err = agentApi.Login(fmt.Sprintf("https://%s:%s/badUrl", systemIP, Vsphere1Port),
				"user", "pass")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusBadRequest))
			zap.S().Info("Invalid URL. Successfully returned http status: BadRequest.")

			res, err = agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))
			zap.S().Info("Correct credentials. Successfully returned http status: NoContent(204).")

			zap.S().Info("Vcenter login tests completed successfully")
		})
	})

	Context("Flow", func() {
		It("Up to date", func() {
			res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))
			zap.S().Info("Vcenter login completed successfully. Credentials saved.")

			zap.S().Infof("Wait for agent status to be %s...", string(v1alpha1.AgentStatusUpToDate))
			Eventually(func() bool {
				return AgentIsUpToDate(svc, source.Id)
			}, "6m", "2s").Should(BeTrue())
		})

		It("Source removal", func() {
			res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))
			zap.S().Info("Vcenter login completed successfully. Credentials saved.")

			zap.S().Infof("Wait for agent status to be %s...", string(v1alpha1.AgentStatusUpToDate))
			Eventually(func() bool {
				return AgentIsUpToDate(svc, source.Id)
			}, "6m", "2s").Should(BeTrue())

			err = svc.RemoveSource(source.Id)
			Expect(err).To(BeNil())

			_, err = svc.GetSource(source.Id)
			Expect(err).To(MatchError(ContainSubstring(fmt.Sprintf("code: %d", http.StatusNotFound))))
		})

		It("Two agents, Two VSphere's", func() {

			res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))
			zap.S().Info("Vcenter login completed successfully. Credentials saved.")

			zap.S().Infof("Wait for agent status to be %s...", string(v1alpha1.AgentStatusUpToDate))
			Eventually(func() bool {
				return AgentIsUpToDate(svc, source.Id)
			}, "6m", "2s").Should(BeTrue())

			source2, err := svc.CreateSource("source-2")
			Expect(err).To(BeNil())
			Expect(source2).NotTo(BeNil())

			agent2, err := CreateAgent(defaultConfigPath, "2", source2.Id, vmName+"-2")
			Expect(err).To(BeNil())

			var agentIP2 string
			Eventually(func() error {
				return FindAgentIp(agent2, &agentIP2)
			}, "4m", "2s").Should(BeNil())

			Eventually(func() bool {
				return IsPlannerAgentRunning(agent2, agentIP2)
			}, "4m", "2s").Should(BeTrue())

			agent2Api, err := agent2.AgentApi()
			Expect(err).To(BeNil())

			Eventually(func() string {
				return CredentialURL(svc, source2.Id)
			}, "4m", "2s").Should(Equal(fmt.Sprintf("https://%s:3333", agentIP2)))

			// Login to Vcsim2
			res, err = agent2Api.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere2Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))
			zap.S().Info("Vcenter login completed successfully. Credentials saved.")

			zap.S().Infof("Wait for agent status to be %s...", string(v1alpha1.AgentStatusUpToDate))
			Eventually(func() bool {
				return AgentIsUpToDate(svc, source2.Id)
			}, "6m", "2s").Should(BeTrue())

			err = agent2.Remove()
			Expect(err).To(BeNil())
		})
	})

	Context("Edge cases", func() {
		It("VM reboot", func() {
			res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))
			zap.S().Info("Vcenter login completed successfully. Credentials saved.")

			// Restarting the VM
			err = agent.Restart()
			Expect(err).To(BeNil())

			// Check that planner-agent service is running
			Eventually(func() bool {
				return agent.IsServiceRunning(agentIP, "planner-agent")
			}, "6m", "2s").Should(BeTrue())

			zap.S().Infof("Wait for agent status to be %s...", string(v1alpha1.AgentStatusUpToDate))
			Eventually(func() bool {
				return AgentIsUpToDate(svc, source.Id)
			}, "6m", "2s").Should(BeTrue())
		})
	})
})

var _ = Describe("e2e-download-ova-from-url", func() {

	var (
		svc       PlannerService
		agent     PlannerAgent
		agentApi  PlannerAgentAPI
		agentIP   string
		err       error
		source    *v1alpha1.Source
		startTime time.Time
	)

	BeforeEach(func() {
		startTime = time.Now()
		testOptions.downloadImageByUrl = true
		testOptions.disconnectedEnvironment = false

		svc, err = NewPlannerService(defaultConfigPath)
		Expect(err).To(BeNil(), "Failed to create PlannerService")

		source, err = svc.CreateSource("source")
		Expect(err).To(BeNil())
		Expect(source).NotTo(BeNil())

		agent, err = CreateAgent(defaultConfigPath, defaultAgentTestID, source.Id, vmName)
		Expect(err).To(BeNil())

		zap.S().Info("Wait for agent IP...")
		Eventually(func() error {
			return FindAgentIp(agent, &agentIP)
		}, "4m", "2s").Should(BeNil())
		zap.S().Infof("Agent ip is: %s", agentIP)

		zap.S().Info("Wait for planner-agent to be running...")
		Eventually(func() bool {
			return IsPlannerAgentRunning(agent, agentIP)
		}, "4m", "2s").Should(BeTrue())
		zap.S().Info("Planner-agent is running")

		agentApi, err = agent.AgentApi()
		Expect(err).To(BeNil(), "Failed to create agent localApi")

		Eventually(func() string {
			return CredentialURL(svc, source.Id)
		}, "4m", "2s").Should(Equal(fmt.Sprintf("https://%s:3333", agentIP)))

		zap.S().Info("Setup complete for test.\n")
	})

	AfterEach(func() {
		zap.S().Info("Cleaning up after test...")
		err = svc.RemoveSources()
		Expect(err).To(BeNil(), "Failed to remove sources from DB")
		err = agent.Remove()
		Expect(err).To(BeNil(), "Failed to remove vm and iso")
		zap.S().Infof("Spec took %s\n", time.Since(startTime))
	})

	AfterFailed(func() {
		agent.DumpLogs(agentIP)
	})

	Context("Flow", func() {
		It("Downloads OVA file from URL", func() {
			res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", systemIP, Vsphere1Port),
				"core", "123456")
			Expect(err).To(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusNoContent))

			zap.S().Infof("Wait for agent status to be %s...", string(v1alpha1.AgentStatusUpToDate))
			Eventually(func() bool {
				return AgentIsUpToDate(svc, source.Id)
			}, "6m", "2s").Should(BeTrue())
		})
	})
})
var _ = Describe("e2e-disconnected-environment", func() {

	var (
		svc       PlannerService
		agent     PlannerAgent
		agentApi  PlannerAgentAPI
		agentIP   string
		err       error
		source    *v1alpha1.Source
		startTime time.Time
	)

	BeforeEach(func() {
		startTime = time.Now()
		testOptions.downloadImageByUrl = false
		testOptions.disconnectedEnvironment = true

		svc, err = NewPlannerService(defaultConfigPath)
		Expect(err).To(BeNil(), "Failed to create PlannerService")

		source, err = svc.CreateSource("source")
		Expect(err).To(BeNil())
		Expect(source).NotTo(BeNil())

		agent, err = CreateAgent(defaultConfigPath, defaultAgentTestID, source.Id, vmName)
		Expect(err).To(BeNil())

		zap.S().Info("Wait for agent IP...")
		Eventually(func() error {
			return FindAgentIp(agent, &agentIP)
		}, "4m", "2s").Should(BeNil())
		zap.S().Infof("Agent ip is: %s", agentIP)

		zap.S().Info("Wait for planner-agent to be running...")
		Eventually(func() bool {
			return IsPlannerAgentRunning(agent, agentIP)
		}, "4m", "2s").Should(BeTrue())
		zap.S().Info("Planner-agent is running")

		agentApi, err = agent.AgentApi()
		Expect(err).To(BeNil(), "Failed to create agent localApi")

		zap.S().Info("Wait for agent server to start...")
		Eventually(func() bool {
			if _, err := agentApi.Status(); err != nil {
				return false
			}
			return true
		}, "5m", "2s").Should(BeTrue())
		zap.S().Info("Agent server started successfully")

		zap.S().Info("Setup complete for test.\n")
	})

	AfterEach(func() {
		zap.S().Info("Cleaning up after test...")
		err = svc.RemoveSources()
		Expect(err).To(BeNil(), "Failed to remove sources from DB")
		err = agent.Remove()
		Expect(err).To(BeNil(), "Failed to remove vm and iso")
		zap.S().Infof("Spec took %s\n", time.Since(startTime))
	})

	AfterFailed(func() {
		agent.DumpLogs(agentIP)
	})

	Context("Flow", func() {
		It("disconnected-environment", func() {

			// Adding vcenter.com to /etc/hosts to enable connectivity to the vSphere server.
			_, err := RunSSHCommand(agentIP, fmt.Sprintf("podman exec "+
				"--user root "+
				"planner-agent "+
				"bash -c 'echo \"%s vcenter.com\" >> /etc/hosts'", systemIP))
			Expect(err).To(BeNil(), "Failed to enable connection to Vsphere")

			// Login to Vcenter
			Eventually(func() bool {
				res, err := agentApi.Login(fmt.Sprintf("https://%s:%s/sdk", "vcenter.com", Vsphere1Port), "core", "123456")
				return err == nil && res.StatusCode == http.StatusNoContent
			}, "3m", "2s").Should(BeTrue())
			zap.S().Info("Vcenter login completed successfully. Credentials saved.")

			zap.S().Info("Wait for the inventory collection process to complete...")
			Eventually(func() bool {
				statusReply, err := agentApi.Status()
				if err != nil {
					return false
				}
				Expect(statusReply.Connected).Should(Equal("false"))
				return statusReply.Connected == "false" && statusReply.Status == string(v1alpha1.AgentStatusUpToDate)
			}, "8m", "2s").Should(BeTrue())
			zap.S().Info("Inventory collection process completed successfully.")

			// Get inventory
			inventory, err := agentApi.Inventory()
			Expect(err).To(BeNil())

			// Manually upload the collected inventory data
			err = svc.UpdateSource(source.Id, inventory)
			Expect(err).To(BeNil())

			// Verify that the inventory upload was successful
			source, err = svc.GetSource(source.Id)
			Expect(err).To(BeNil())
			Expect(source.Agent).To(Not(BeNil()))
			Expect(source.Agent.Status).Should(Equal(v1alpha1.AgentStatusNotConnected))
			Expect(source.Agent.CredentialUrl).Should(BeEmpty())
			Expect(source.Inventory).To(Equal(inventory))
		})
	})
})
