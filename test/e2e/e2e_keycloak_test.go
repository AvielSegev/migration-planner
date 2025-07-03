package e2e_test

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type User struct {
	Username     string
	Organization string
	Token        *jwt.Token
}

var _ = Describe("e2e-test keyclock", func() {

	var (
		err      error
		ctx      = context.Background()
		keycloak = DefaultKeyClock()
	)

	BeforeEach(func() {

		//////////////////// Remove relm

		err = keycloak.LoginAdmin(ctx, "master")
		Expect(err).To(BeNil())
		err = keycloak.DeleteRealm(ctx)
		Expect(err).To(BeNil())

		///////////////////

		if err := keycloak.init(ctx); err != nil {
			panic(err)
		}

		if err := keycloak.CreateUser(ctx,
			"Aviel",
			"123456",
			"redhat",
			"Aviel",
			"segev",
			"asegev@redhat.com",
		); err != nil {
			panic(err)
		}

		token, err := keycloak.GetToken(ctx, "aviel", "123456", keycloak.realmName)
		if err != nil {
			panic(err)
		}

		tokenstr := token.AccessToken
		fmt.Printf("token: %s\n", tokenstr)
	})

	It("empty test", func() {
		Expect(nil).To(BeNil())
	})

})
