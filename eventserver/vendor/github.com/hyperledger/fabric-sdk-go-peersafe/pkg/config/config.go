/*
Copyright SecureKey Technologies Inc. All Rights Reserved.


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at


      http://www.apache.org/licenses/LICENSE-2.0


Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"github.com/spf13/viper"
)

// PeerConfig A set of configurations required to connect to a Fabric peer
type PeerConfig struct {
	Address    string
	EventHost  string
	EventPort  int
	Primary    bool
	LocalMspId string
	TLS        struct {
		Certificate        string
		ServerHostOverride string
	}
}

// GetPeersConfig Retrieves the fabric peers from the config file provided
func GetPeersConfig() ([]PeerConfig, error) {
	peersConfig := []PeerConfig{}
	err := viper.UnmarshalKey("client.peers", &peersConfig)
	if err != nil {
		return nil, err
	}
	for index, p := range peersConfig {
		if p.Address == "" {
			return nil, fmt.Errorf("Address key not exist or empty for peer %d", index)
		}
		if p.LocalMspId == "" {
			return nil, fmt.Errorf("Msp id not exist or empty for peer %d", index)
		}
		if IsTLSEnabled() && p.TLS.Certificate == "" {
			return nil, fmt.Errorf("tls.certificate not exist or empty for peer %d", index)
		}
		//peersConfig[index].TLS.Certificate = filepath.Join(viper.GetString("peer.fileSystemPath"), p.TLS.Certificate)
	}
	return peersConfig, nil
}

// IsTLSEnabled ...
func IsTLSEnabled() bool {
	return viper.GetBool("peer.tls.enabled")
}

func GetOrdererAddress() string {
	return viper.GetString("client.orderer.address")
}

func GetOrderCaFile() string {
	return viper.GetString("client.orderer.tls.certificate")
}

func GetOrderServerHostOverride() string {
	return viper.GetString("client.orderer.tls.serverHostOverride")
}

func IsTracerEnabled() bool {
	return viper.GetBool("chaincode.tracer.enabled")
}

func GetTracerAddress() string {
	return viper.GetString("chaincode.tracer.address")
}
