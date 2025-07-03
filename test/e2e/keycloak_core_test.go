package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Nerzal/gocloak/v13"
	. "github.com/kubev2v/migration-planner/test/e2e"
	"os"
)

type Keycloak struct {
	client          *gocloak.GoCloak
	masterRealmUser string
	masterRealmPass string
	realmName       string
	adminToken      *gocloak.JWT
}

func DefaultKeyClock() *Keycloak {
	keycloak := NewKeyClock(
		DefaultKeyCloakUrl,
		DefaultKeyCloakAdminUsername,
		DefaultKeyCloakAdminPassword,
		DefaultKeyCloakRealm,
	)

	restyClient := keycloak.client.RestyClient()
	restyClient.SetDebug(true)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	return keycloak
}

func NewKeyClock(keyClockBaseUrl, user, pass, realm string) *Keycloak {
	return &Keycloak{
		client:          gocloak.NewClient(keyClockBaseUrl),
		masterRealmUser: user,
		masterRealmPass: pass,
		realmName:       realm,
	}
}

func (k *Keycloak) init(ctx context.Context) error {
	if err := k.LoginAdmin(ctx, "master"); err != nil {
		return err
	}

	if err := k.createRealm(ctx, k.realmName); err != nil {
		return err
	}

	if err := k.loadPlannerAuthKeys(ctx, PrivateKeyPath); err != nil {
		return err
	}

	clientUUID, err := k.CreateClient(ctx, k.realmName)
	if err != nil {
		return err
	}

	if err := k.addOrgIdClaim(ctx, clientUUID); err != nil {
		return err
	}

	//if err := k.removeBadMappers(ctx, clientUUID); err != nil {
	//	return err
	//}

	return nil
}

func (k *Keycloak) LoginAdmin(ctx context.Context, realm string) error {
	token, err := k.client.LoginAdmin(ctx, k.masterRealmUser, k.masterRealmPass, realm)
	if err != nil {
		return err
	}
	k.adminToken = token
	return nil
}

func (k *Keycloak) CreateClient(ctx context.Context, clientID string) (string, error) {
	cli := gocloak.Client{
		ClientID:                  gocloak.StringP(clientID),
		Enabled:                   gocloak.BoolP(true),
		PublicClient:              gocloak.BoolP(true),
		StandardFlowEnabled:       gocloak.BoolP(true),
		DirectAccessGrantsEnabled: gocloak.BoolP(true),
	}

	id, err := k.client.CreateClient(ctx, k.adminToken.AccessToken, k.realmName, cli)
	if err != nil {
		return "", fmt.Errorf("failed to create client %q: %w", clientID, err)
	}

	return id, nil
}

func (k *Keycloak) CreateUser(ctx context.Context, user, pass, org, fn, ln, email string) error {

	userRep := gocloak.User{
		Username:      gocloak.StringP(user),
		Enabled:       gocloak.BoolP(true),
		FirstName:     gocloak.StringP(fn),
		LastName:      gocloak.StringP(ln),
		Email:         gocloak.StringP(email),
		EmailVerified: gocloak.BoolP(true),
		Attributes:    &map[string][]string{"organization": {org}},
	}

	userID, err := k.client.CreateUser(ctx, k.adminToken.AccessToken, k.realmName, userRep)
	if err != nil {
		return err
	}

	if err = k.client.SetPassword(ctx, k.adminToken.AccessToken, userID, k.realmName, pass, false); err != nil {
		return err
	}

	return nil
}

func (k *Keycloak) createRealm(ctx context.Context, realmName string) error {

	if _, err := k.client.GetRealm(ctx, k.adminToken.AccessToken, realmName); err == nil {
		return nil
	}

	realmRepresentation := gocloak.RealmRepresentation{
		Realm:               &realmName,
		Enabled:             gocloak.BoolP(true),
		AccessTokenLifespan: gocloak.IntP(3600),
	}

	if _, err := k.client.CreateRealm(ctx, k.adminToken.AccessToken, realmRepresentation); err != nil {
		return err
	}

	return nil
}

func (k *Keycloak) ImportPrivateKey(keyFilePath string) (string, error) {
	keyBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file %q: %w", keyFilePath, err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("expected PEM block type RSA PRIVATE KEY, got %v", block)
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS#1 key: %w", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PKCS#8: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

func (k *Keycloak) ImportPublicKey(keyFilePath string) (string, error) {
	keyBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file %q: %w", keyFilePath, err)
	}
	block, _ := pem.Decode(keyBytes)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS#1 key: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}

	return string(pem.EncodeToMemory(pubBlock)), nil
}

func (k *Keycloak) loadPlannerAuthKeys(ctx context.Context, filePath string) error {
	privateKey, err := k.ImportPrivateKey(filePath)
	if err != nil {
		return err
	}

	publicKey, err := k.ImportPublicKey(filePath)
	if err != nil {
		return err
	}

	fmt.Printf("Public Key: %s\n", publicKey)

	comp := gocloak.Component{
		Name:         gocloak.StringP("rsa-key-" + k.realmName),
		ProviderID:   gocloak.StringP("rsa"),
		ProviderType: gocloak.StringP("org.keycloak.keys.KeyProvider"),
		ParentID:     gocloak.StringP(k.realmName),
		ComponentConfig: &map[string][]string{
			"priority":   {"100"},
			"privateKey": {privateKey},
			"publicKey":  {publicKey},
			"enabled":    {"true"},
			"active":     {"true"},
		},
	}

	if _, err := k.client.CreateComponent(ctx, k.adminToken.AccessToken, k.realmName, comp); err != nil {
		return fmt.Errorf("failed to import private key into realm %s: %w", k.realmName, err)
	}

	return nil
}

//
//func (k *Keycloak) listProtocolMappers(clientUUID string) ([]gocloak.ProtocolMapperRepresentation, error) {
//	url := fmt.Sprintf(
//		"%s/admin/realms/%s/clients/%s/protocol-mappers/models",
//		DefaultKeyCloakUrl, // e.g. "http://192.168.7.7:8080"
//		k.realmName,        // "planner"
//		clientUUID,         // e.g. "32153262-3de0-4c8d-839d-ede547ffd25d"
//	)
//
//	resp, err := k.client.RestyClient().
//		R().
//		SetAuthToken(k.adminToken.AccessToken).
//		SetResult(&[]gocloak.ProtocolMapperRepresentation{}).
//		Get(url)
//	if err != nil {
//		return nil, fmt.Errorf("failed to list protocol mappers: %w", err)
//	}
//
//	mappers := *resp.Result().(*[]gocloak.ProtocolMapperRepresentation)
//	return mappers, nil
//}
//
//func (k *Keycloak) removeBadMappers(ctx context.Context, clientUUID string) error {
//	mappers, err := k.listProtocolMappers(clientUUID)
//	if err != nil {
//		return err
//	}
//
//	bad := map[string]struct{}{
//		"given name":      {},
//		"family name":     {},
//		"email":           {},
//		"name":            {},
//		"email_verified":  {},
//		"scope":           {},
//		"realm_access":    {},
//		"resource_access": {},
//		"acr":             {},
//		"sid":             {},
//		"azp":             {},
//		"typ":             {},
//	}
//
//	for _, m := range mappers {
//		name := m.Name
//		if _, should := bad[*name]; should {
//			if err := k.client.DeleteClientProtocolMapper(
//				ctx,
//				k.adminToken.AccessToken,
//				k.realmName,
//				clientUUID,
//				*m.ID,
//			); err != nil {
//				return fmt.Errorf("failed to delete mapper %q: %w", *name, err)
//			}
//		}
//	}
//
//	return nil
//}

func (k *Keycloak) addOrgIdClaim(ctx context.Context, clientUUID string) error {
	mapper := gocloak.ProtocolMapperRepresentation{
		Name:           gocloak.StringP("org_id"),
		Protocol:       gocloak.StringP("openid-connect"),
		ProtocolMapper: gocloak.StringP("oidc-usermodel-attribute-mapper"),
		Config: &map[string]string{
			"user.attribute":       "organization",
			"claim.name":           "org_id",
			"jsonType.label":       "String",
			"access.token.claim":   "true",
			"id.token.claim":       "false",
			"userinfo.token.claim": "false",
		},
	}

	if _, err := k.client.CreateClientProtocolMapper(
		ctx,
		k.adminToken.AccessToken,
		k.realmName,
		clientUUID,
		mapper,
	); err != nil {
		return fmt.Errorf("failed to create org_id mapper: %w", err)
	}

	return nil
}

func (k *Keycloak) GetToken(ctx context.Context, user, pass, clientID string) (*gocloak.JWT, error) {
	options := gocloak.TokenOptions{
		ClientID:  gocloak.StringP(clientID),
		Username:  gocloak.StringP(user),
		Password:  gocloak.StringP(pass),
		GrantType: gocloak.StringP("password"),
	}

	token, err := k.client.GetToken(ctx, k.realmName, options)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (k *Keycloak) DeleteRealm(ctx context.Context) error {
	if err := k.client.DeleteRealm(ctx, k.adminToken.AccessToken, k.realmName); err != nil {
		return fmt.Errorf("failed to delete realm %q: %w", k.realmName, err)
	}
	return nil
}
