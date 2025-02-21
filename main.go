package ssh_push_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"time"
)

type UserConfig struct {
	Username string `json:"username"`
	PubKey   string `json:"pubkey"`
}

type CommandToUser struct {
	Command string `json:"command"`
	User    string `json:"user"`
}

type LoginHistory struct {
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	IPAddress string    `json:"ip_address"`
}

type CommandHistory struct {
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	Command   string    `json:"command"`
}

var userConfigs []UserConfig
var commandToUser []CommandToUser
var loginHistory []LoginHistory
var commandHistory []CommandHistory

const (
	userConfigFile     = "user_config.json"
	commandToUserFile  = "command_to_user.json"
	loginHistoryFile   = "login_history.json"
	commandHistoryFile = "command_history.json"
)

func loadConfig() {
	// Load user config
	data, err := ioutil.ReadFile(userConfigFile)
	if err != nil {
		log.Fatalf("Error reading user config file: %s", err)
	}
	if err := json.Unmarshal(data, &userConfigs); err != nil {
		log.Fatalf("Error unmarshalling user config: %s", err)
	}

	// Load command-to-user mappings
	data, err = ioutil.ReadFile(commandToUserFile)
	if err != nil {
		log.Fatalf("Error reading command-to-user file: %s", err)
	}
	if err := json.Unmarshal(data, &commandToUser); err != nil {
		log.Fatalf("Error unmarshalling command-to-user mappings: %s", err)
	}

	// Load history logs if available
	loadHistory()
}

func loadHistory() {
	// Load login history
	data, err := ioutil.ReadFile(loginHistoryFile)
	if err == nil {
		json.Unmarshal(data, &loginHistory)
	}

	// Load command history
	data, err = ioutil.ReadFile(commandHistoryFile)
	if err == nil {
		json.Unmarshal(data, &commandHistory)
	}
}

func saveHistory() {
	// Save login history
	loginData, err := json.Marshal(loginHistory)
	if err != nil {
		log.Printf("Error saving login history: %s", err)
	} else {
		ioutil.WriteFile(loginHistoryFile, loginData, 0644)
	}

	// Save command history
	commandData, err := json.Marshal(commandHistory)
	if err != nil {
		log.Printf("Error saving command history: %s", err)
	} else {
		ioutil.WriteFile(commandHistoryFile, commandData, 0644)
	}
}

func getUserPubKey(username string) (ssh.PublicKey, error) {
	for _, user := range userConfigs {
		if user.Username == username {
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.PubKey))
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
			return pubKey, nil
		}
	}
	return nil, fmt.Errorf("no pubkey found for user %s", username)
}

func logLogin(username, ipAddress string) {
	loginHistory = append(loginHistory, LoginHistory{
		Timestamp: time.Now(),
		Username:  username,
		IPAddress: ipAddress,
	})
	saveHistory()
}

func logCommand(username, command string) {
	commandHistory = append(commandHistory, CommandHistory{
		Timestamp: time.Now(),
		Username:  username,
		Command:   command,
	})
	saveHistory()
}

func handleSession(s ssh.Session) {
	username := s.User()
	ipAddress := s.RemoteAddr().String()

	// Log login attempt
	logLogin(username, ipAddress)

	// Read command from the client
	command := string(s.Command())
	// Log the executed command
	logCommand(username, command)

	// Check if the command needs to be executed as another user
	var targetUser string
	for _, mapping := range commandToUser {
		if command == mapping.Command {
			targetUser = mapping.User
			break
		}
	}

	if targetUser != "" {
		// Execute the command as the specified user
		executeCommandAsUser(targetUser, command, s)
	} else {
		// Return success without executing anything
		s.Write([]byte("Command received. No special action taken.\n"))
	}
}

func executeCommandAsUser(user, command string, s ssh.Session) {
	// Prepare to execute the command as a different user using `sudo`
	cmd := exec.Command("sudo", "-u", user, "/bin/sh", "-c", command)

	var out bytes.Buffer
	cmd.Stdout = &out
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err := cmd.Run()

	if err != nil {
		s.Write([]byte("Error executing command: " + errOut.String() + "\n"))
		return
	}

	s.Write(out.Bytes())
}

func main() {
	// Load configuration files
	loadConfig()

	// Setup SSH server config
	config := &ssh.ServerConfig{
		NoClientAuth: false,
	}

	// Add user public keys
	for _, user := range userConfigs {
		pubKey, err := getUserPubKey(user.Username)
		if err != nil {
			log.Printf("Error getting pubkey for user %s: %s", user.Username, err)
			continue
		}
		config.AddHostKey(pubKey)
	}

	// Start the SSH server
	listener, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatalf("Failed to listen on port 2222: %s", err)
	}

	for {
		// Accept incoming SSH connections
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %s", err)
			continue
		}

		// Handshake and authenticate the client
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake: %s", err)
			continue
		}

		// Start a goroutine for handling the incoming requests
		go ssh.DiscardRequests(reqs)
		for newChannel := range chans {
			// Handle the session channel
			if newChannel.ChannelType() == "session" {
				channel, _, err := newChannel.Accept()
				if err != nil {
					log.Printf("Failed to accept channel: %s", err)
					continue
				}

				// Handle the session
				go handleSession(channel)
			}
		}
	}
}
