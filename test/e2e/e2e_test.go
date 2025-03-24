package e2e_test

import (
	"fmt"
	"net/http"
	"os"

	"github.com/kubev2v/migration-planner/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	Vsphere1Port string = "8989"
	Vsphere2Port string = "8990"
)

var (
	svc      PlannerService
	agent    PlannerAgent
	agentIP  string
	err      error
	systemIP = os.Getenv("PLANNER_IP")
	source   *v1alpha1.Source
)

var testOptions = struct {
	downloadImageByUrl      bool
	disconnectedEnvironment bool
}{}

var _ = Describe("e2e", func() {

	BeforeEach(func() {
		testOptions.downloadImageByUrl = false
		testOptions.disconnectedEnvironment = false

		svc, err = NewPlannerService(defaultConfigPath)
		Expect(err).To(BeNil(), "Failed to create PlannerService")

		source = CreateSource("source")

		agent, agentIP = CreateAgent(defaultConfigPath, defaultAgentTestID, source.Id, vmName)

		WaitForValidCredentialURL(source.Id, agentIP)
	})

	AfterEach(func() {
		err = svc.RemoveSources()
		Expect(err).To(BeNil(), "Failed to remove sources from DB")
		err = agent.Remove()
		Expect(err).To(BeNil(), "Failed to remove vm and iso")
	})

	AfterFailed(func() {
		agent.DumpLogs(agentIP)
	})

	Context("Check Vcenter login behavior", func() {
		It("should successfully login with valid credentials", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "core", "123456", http.StatusNoContent)
		})

		It("Two test combined: should return BadRequest due to an empty username"+
			" and BadRequest due to an empty password", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "", "pass", http.StatusBadRequest)
			LoginToVsphere(agent, systemIP, Vsphere1Port, "user", "", http.StatusBadRequest)
		})

		It("should return Unauthorized due to invalid credentials", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "invalid", "cred", http.StatusUnauthorized)
		})

		It("should return badRequest due to an invalid URL", func() {
			LoginToVsphere(agent, systemIP, "", "user", "pass", http.StatusBadRequest)
		})

	})

	Context("Flow", func() {
		It("Up to date", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "core", "123456", http.StatusNoContent)

			WaitForAgentToBeUpToDate(source.Id)
		})

		It("Source removal", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "core", "123456", http.StatusNoContent)

			WaitForAgentToBeUpToDate(source.Id)

			err = svc.RemoveSource(source.Id)
			Expect(err).To(BeNil())

			_, err = svc.GetSource(source.Id)
			Expect(err).To(MatchError(ContainSubstring(fmt.Sprintf("code: %d", http.StatusNotFound))))
		})

		It("Two agents, Two VSphere's", func() {

			LoginToVsphere(agent, systemIP, Vsphere1Port, "core", "123456", http.StatusNoContent)
			WaitForAgentToBeUpToDate(source.Id)

			source2 := CreateSource("source-2")

			agent2, agentIP2 := CreateAgent(defaultConfigPath, "2", source2.Id, vmName+"-2")

			WaitForValidCredentialURL(source2.Id, agentIP2)

			// Login to Vcsim2
			LoginToVsphere(agent2, systemIP, Vsphere2Port, "core", "123456", http.StatusNoContent)

			WaitForAgentToBeUpToDate(source2.Id)

			err = agent2.Remove()
			Expect(err).To(BeNil())
		})
	})

	Context("Edge cases", func() {
		It("VM reboot", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "core", "123456", http.StatusNoContent)

			// Restarting the VM
			err = agent.Restart()
			Expect(err).To(BeNil())

			// Check that planner-agent service is running
			Eventually(func() bool {
				return agent.IsServiceRunning(agentIP, "planner-agent")
			}, "6m").Should(BeTrue())

			WaitForAgentToBeUpToDate(source.Id)
		})
	})
})

var _ = Describe("e2e-download-ova-from-url", func() {

	BeforeEach(func() {
		testOptions.downloadImageByUrl = true
		testOptions.disconnectedEnvironment = false

		svc, err = NewPlannerService(defaultConfigPath)
		Expect(err).To(BeNil(), "Failed to create PlannerService")

		source = CreateSource("source")

		agent, agentIP = CreateAgent(defaultConfigPath, defaultAgentTestID, source.Id, vmName)

		WaitForValidCredentialURL(source.Id, agentIP)
	})

	AfterEach(func() {
		err = svc.RemoveSources()
		Expect(err).To(BeNil(), "Failed to remove sources from DB")
		err = agent.Remove()
		Expect(err).To(BeNil(), "Failed to remove vm and iso")
	})

	AfterFailed(func() {
		agent.DumpLogs(agentIP)
	})

	Context("Flow", func() {
		It("Downloads OVA file from URL", func() {
			LoginToVsphere(agent, systemIP, Vsphere1Port, "core", "123456", http.StatusNoContent)

			WaitForAgentToBeUpToDate(source.Id)
		})
	})
})

var _ = Describe("e2e-disconnected-environment", func() {

	BeforeEach(func() {
		testOptions.downloadImageByUrl = false
		testOptions.disconnectedEnvironment = true

		svc, err = NewPlannerService(defaultConfigPath)
		Expect(err).To(BeNil(), "Failed to create PlannerService")

		source = CreateSource("source")

		agent, agentIP = CreateAgent(defaultConfigPath, defaultAgentTestID, source.Id, vmName)

		Eventually(func() bool {
			if _, err := agent.Status(); err != nil {
				return false
			}
			return true
		}, "5m").Should(BeTrue())
	})

	AfterEach(func() {
		err = svc.RemoveSources()
		Expect(err).To(BeNil(), "Failed to remove sources from DB")
		err = agent.Remove()
		Expect(err).To(BeNil(), "Failed to remove vm and iso")
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
				res, err := agent.Login(fmt.Sprintf("https://%s:%s/sdk", "vcenter.com", Vsphere1Port), "core", "123456")
				return err == nil && res.StatusCode == http.StatusNoContent
			}, "3m").Should(BeTrue())

			Eventually(func() bool {
				statusReply, err := agent.Status()
				if err != nil {
					return false
				}
				Expect(statusReply.Connected).Should(Equal("false"))
				return statusReply.Connected == "false" && statusReply.Status == "up-to-date"
			}, "4m").Should(BeTrue())

			inventory, err := agent.Inventory()
			Expect(err).To(BeNil())

			err = svc.UpdateSource(source.Id, inventory)
			Expect(err).To(BeNil())
		})
	})
})
