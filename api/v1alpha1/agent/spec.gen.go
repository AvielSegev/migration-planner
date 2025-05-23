// Package v1alpha1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package v1alpha1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	externalRef0 "github.com/kubev2v/migration-planner/api/v1alpha1"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+xYTXPbNhD9Kxy0R0qUnfSim+0kjaZ16oknySHjw5pYiYhJgAWW0rgZ/vcOAFKiRIiS",
	"XLvTdnqzhcV+vH14WPA7S1VRKomSDJt+ZybNsAD358UCJdk/Sq1K1CTQ/ZxqBEJ+4ZbmShdAbMo4EI5I",
	"FMhiRo8lsikzpIVcsDq2WzhKEpB/0rnd1rMQfMtbVQkecmQIqHJZoKwKNv3KpKJRqqTElNBuWYEgIRej",
	"udKjTVjDYoZaK81itgDK0DocCSns4kjIJUpS+pHFrCpHpEa2GhYzoyqd4mihJLK7venM5FwFi6pKfipS",
	"S9RGKBlwV8dM4++V0Mht3Q6fBo6tRHbRjjsN66a0ibWpTN1/w5RsHq73t87rJ7clyIMDTfXwzU5t7akw",
	"H43ZcXC17jr5hxB6AwSGlA4gw4V58FX3cp1rxCsoIRX0+PNlx0RIwgVqa5OB5ivQeJGmmKO2/bpWS+wY",
	"3yuVI0hrTIogP+TR/xKETnKlDyPnVvvBevWsPcYtCPvLCYH61p3RHqAFGgMLVwJHk2pRkmu4t4/a5fhA",
	"Fa3dXR2zmZxrCLSu7ar7TxAW7o8fNc7ZlP2QbMQyaZQy2RBhjTQDreHR9VIZulEr1PYseafAubDpQ36z",
	"FXpf2zrwWG/mBvVVXhlCvZXi3u3rXCTSSumH7cp2yl+alaA0C5JFQhFmUUuvVpMNgeSguWcBaXFfeXFe",
	"u49ZJU1VlkrbhZC0LnOQwTMUZqbLLcSoXRA8hT1++3CzJu8t1KH13fgb413n/X71+dDpStwlX6iU2fqa",
	"6vVNtGweIqqnvMU2RdnQZ8j+85U3szsOH4PP16YHThvIO4ibNEO1XYuFBnsqZsZUOERRMAaNKZrRpD9q",
	"qGprpdPXHO4xP8wobxZ3A7VujyHYrbs0Anm309QQiH7kquOnDFlHjlCiy6JhurSGQ2dfyRuNhTBbGta5",
	"n06egUJzjou+f5Dp5BDqkO/I8DDjujN7OQR3q+pMnG3oUOrtEewfeH7UiBj0ef0R/WRzqREeuFrJvv9M",
	"GFILDUX4ijzx5imE/Ax5hWFrQ1geobRrJ80Or5fhM2l1eEDc3yntBQfuczzW7oug7AtoKeTCDO/5oGjY",
	"/U5lG7Db1IN5HkxqXwZhFgS0NS2rq3b2Gdb6PoVqP/Jdtfr7xP1+hH3C5qK9Qbo9GvKze+VYlevC9hHB",
	"KPkUN+qvznnls02MGoonI3roFB11hI4/P6HBivVDxRuWtuWtmdOloGvDNpR7GhziTv/I1E75/RM0FylK",
	"48r2FyO7KCHNMDofT+zdZN/DLCMqzTRJVqvVGNzyWOlF0uw1ya+zq7cfbt+OzseTcUZF7iATZNHcjEPR",
	"TQ5Soo4ubmbRKHJ3RYSSl0rI7ht+yirJcS4kcsfAEiWUgk3Zq/FkfGZxAMoc7AmUIlmeJc6VSb4LXieb",
	"t3dZUf+V5S/NyFtFah5Rhj4V5kI1/Odr087XAxdaQ4F+3v6663v2ZsubsL/ZXNtbf+ongA0zSFcYN5+p",
	"jriu6zu/GQ1dKu6u7FRJamYxKMtcpC795Jvx3xA2rg9OalszRV17CptSyWYcOp9M+mj+9ovt0PnkbN/S",
	"a7/rWdL0D2qX2XaoS+DRR4+Lj3n28jE/SagoU1r84Vn6evLq5YO+U/pecI7SR3z98hE/KIrmqpKuxp/+",
	"jmbO7JAoIY9uUS9RR61hzAis2H5tXh939qdWALzin6IAxh3V9exqlQAi72aPEPjRe9aZdg+JQaMua6//",
	"GkEIvDLq7TvNJrpHIZ4xgxA//teV/4iuvPuHyUpzTL2uZAg5uU+HCwxoyHu3HKUZpg89ufCL7Nj7s5NC",
	"E/XO5W9col5a/BSWsPqu/jMAAP//ySOXQ+UaAAA=",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	pathPrefix := path.Dir(pathToFile)

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(pathPrefix, "../openapi.yaml")) {
		if _, ok := res[rawPath]; ok {
			// it is not possible to compare functions in golang, so always overwrite the old value
		}
		res[rawPath] = rawFunc
	}
	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
