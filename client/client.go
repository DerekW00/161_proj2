package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!

/*Data Structures*/

// User This is the type definition for the User struct.
type User struct {
	//User Identifiers
	Username string
	UserUUID uuid.UUID
	PWHash   []byte //Password hash

	//User keys
	HMACKey []byte //HMAC key
	EncKey  []byte //Encryption key

	SignKey userlib.DSSignKey //Private Key for file sharing
	DecKey  userlib.PKEDecKey //Private key for sharing Decryption

	//User files
	FilesUUID map[string]uuid.UUID //Files Owned by User to uuid
	Token     map[string]uuid.UUID //Filename to uuid of share tree
	FilesEnc  map[string][]byte    //Encrypted files
	FilesHMAC map[string][]byte    //HMAC for files

	// Sessions
	Sessions map[uuid.UUID]*Session // Map from session ID to Session
	// ValidTokens keeps track of all valid session tokens for this user.
	ValidTokens map[string]bool
}

// GetCurrentSession checks if the provided token is valid.
func (userdata *User) GetCurrentSession(token string) (bool, error) {
	_, valid := userdata.ValidTokens[token]
	if !valid {
		return false, fmt.Errorf("invalid session token: %v", token)
	}
	return true, nil
}

// DatastoreEntity This is the type definition for the DatastoreEntity struct. This is the struct that will be stored in the datastore.
type DatastoreEntity struct {
	Enctxt        []byte
	HMACSignedtxt []byte
}

type Session struct {
	SessionID uuid.UUID // The session identifier
	User      *User     // Pointer to the user that this session belongs to
	// Any other session-related data can be added here
}

// ShareRecord This is the type definition for the ShareRecord struct.
type ShareRecord struct {
	EncKey     []byte
	HMACKey    []byte
	FileMdUUID uuid.UUID
}

type Token struct {
	Token []byte
	Sign  []byte
}

type MetaDataStore struct {
	FileUUID uuid.UUID
	NextUUID uuid.UUID

	//First Block Only
	LastUUID    uuid.UUID
	TotalBlocks int
}

type Node struct {
	Nodeid   uuid.UUID
	Username string
	FileKey  []byte
	Children map[string]uuid.UUID
	Parent   uuid.UUID
}

/*Helper functions*/

func encry(IV []byte, key []byte, plainText []byte) []byte {
	blockSize := userlib.AESBlockSizeBytes
	plainTextLen := len(plainText)

	// Calculate the number of padding bytes needed
	paddingNum := blockSize - (plainTextLen % blockSize)

	// Create a new byte slice with the appropriate size for the padded text
	paddedText := make([]byte, plainTextLen+paddingNum)

	// Copy the original text into the new byte slice
	copy(paddedText, plainText)

	// Add the padding bytes to the end of the text
	for i := 0; i < paddingNum; i++ {
		paddedText[plainTextLen+i] = byte(paddingNum)
	}

	// Encrypt the padded text
	encryptedText := userlib.SymEnc(key, IV, paddedText)

	return encryptedText
}

func decry(cipherText []byte, decryptionKey []byte) []byte {
	// Decrypt the text using the provided key
	textWithPadding := userlib.SymDec(decryptionKey, cipherText)

	// Get the last byte of the decrypted text, which represents the number of padding bytes in PKCS#7
	numOfPadding := int(textWithPadding[len(textWithPadding)-1])

	// Calculate the length of the original text by subtracting the padding
	lengthOfOriginalText := len(textWithPadding) - numOfPadding

	// Create a new byte slice to hold the original text
	plainText := make([]byte, lengthOfOriginalText)

	// Copy the original text from the padded text
	copy(plainText, textWithPadding[:lengthOfOriginalText])

	// Return the original text
	return plainText
}

func hmacSigner(key []byte, encrypted []byte) ([]byte, error) {
	signed, err := userlib.HMACEval(key, encrypted)
	return signed, err
}
func hmacverifier(key []byte, retrieved []byte, original []byte) (bool, error) {
	reHMAC, err := userlib.HMACEval(key, retrieved)
	changed := !userlib.HMACEqual(reHMAC, original)

	if changed {
		return false, err
	} else {
		return true, err
	}
}

func checkUserData(userID uuid.UUID) (*DatastoreEntity, error) {
	retrievedData, dataPresent := userlib.DatastoreGet(userID)
	if !dataPresent {
		return nil, errors.New("GetUser: Invalid User")
	}

	storedData := &DatastoreEntity{}
	if err := json.Unmarshal(retrievedData, storedData); err != nil {
		return nil, errors.New("GetUser: Cannot unmarshal json")
	}

	return storedData, nil
}
func getEncryKeys(username []byte, password []byte) ([]byte, []byte) {

	usertotal := append(username, password...)
	encKey := userlib.Argon2Key(usertotal, []byte("encryption"), userlib.AESKeySizeBytes)
	hmacKey := userlib.Argon2Key(usertotal, []byte("hmacdcddce"), userlib.AESKeySizeBytes)
	return encKey, hmacKey
}

func initroot(userdata *User, filename string) (newRoot Node) {
	// Create root directory
	var root Node
	root.Username = userdata.Username
	root.Children = make(map[string]uuid.UUID)
	rootID := uuid.New()
	root.Nodeid = rootID
	rootJson, _ := json.Marshal(root)
	userlib.DatastoreSet(rootID, rootJson)
	userdata.Token[filename] = rootID

	return root
}
func (userdata *User) bfsSearchOnTree(rootNode Node) Node {
	// BFS search on tree
	queue := make([]Node, 0)
	queue = append(queue, rootNode)

	var userNode Node
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if next.Username == userdata.Username {
			userNode = next
			break
		}
		if len(next.Children) > 0 {
			for _, child := range next.Children {
				childJson, _ := userlib.DatastoreGet(child)
				var childNode Node
				json.Unmarshal(childJson, &childNode)
				queue = append(queue, childNode)
			}
		}
	}
	return userNode
}
func (user *User) newSession() (*Session, error) {
	// Create a new session ID
	sessionID := uuid.New()

	// Create the session
	session := &Session{
		SessionID: sessionID,
		User:      user,
	}

	// Store the session in the user's session map
	user.Sessions[sessionID] = session

	return session, nil
}
func findUserInTree(userdata *User, shareTreeID uuid.UUID) (Node, error) {
	shareTreeJson, ok := userlib.DatastoreGet(shareTreeID)
	if !ok {
		return Node{}, errors.New("AppendFile: fail to get share tree from ds")
	}
	var rootNode Node
	json.Unmarshal(shareTreeJson, &rootNode)

	// BFS search on tree
	queue := make([]Node, 0)
	queue = append(queue, rootNode)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if next.Username == userdata.Username {
			return next, nil
		}
		for _, child := range next.Children {
			childJson, _ := userlib.DatastoreGet(child)
			var childNode Node
			json.Unmarshal(childJson, &childNode)
			queue = append(queue, childNode)
		}
	}

	return Node{}, errors.New("AppendToFile: username not found in sharetree")
}

func retrieveKeysFromNode(userdata *User, node Node) (uuid.UUID, []byte, []byte, error) {
	encRecord := node.FileKey
	decRecordbyte, err := userlib.PKEDec(userdata.DecKey, encRecord)
	if err != nil {
		return uuid.UUID{}, nil, nil, errors.New("AppendToFile: cannot decrypt node in sharetree")
	}
	var decRecord ShareRecord
	json.Unmarshal(decRecordbyte, &decRecord)

	// Return metadata UUID and file keys from the shareRecord struct
	return decRecord.FileMdUUID, decRecord.EncKey, decRecord.HMACKey, nil
}

func storeNewData(encKey, hmacKey, data []byte) uuid.UUID {
	fileuuid := uuid.New()
	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	var filedataEntity DatastoreEntity
	ciphertxt := encry(IV, encKey, data)
	filedataEntity.Enctxt = ciphertxt
	filedataEntity.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	entityJSON, _ := json.Marshal(filedataEntity)
	userlib.DatastoreSet(fileuuid, entityJSON)
	return fileuuid
}

func getMetadata(UUID uuid.UUID, encKey, hmacKey []byte) (MetaDataStore, error) {
	marshaledMdEntity, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return MetaDataStore{}, errors.New("AppendToFile: fail to get metadata from ds")
	}
	var metaEntity DatastoreEntity
	json.Unmarshal(marshaledMdEntity, &metaEntity)
	hmac, _ := hmacverifier(hmacKey, metaEntity.Enctxt, metaEntity.HMACSignedtxt)
	if !hmac {
		return MetaDataStore{}, errors.New("AppendToFile: metadata hmac fail")
	}
	metadataJson := decry(metaEntity.Enctxt, encKey)
	var metadataDec MetaDataStore
	json.Unmarshal(metadataJson, &metadataDec)
	return metadataDec, nil
}

func manageMetadata(mdLast MetaDataStore, fileUUID uuid.UUID, encKey, hmacKey []byte) (uuid.UUID, error) {
	newLastmd := MetaDataStore{FileUUID: fileUUID}
	newLastmdUUID := uuid.New()

	IV1 := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	newLastmdjson, _ := json.Marshal(newLastmd)
	var mdnewLastEnt DatastoreEntity
	ciphertxt := encry(IV1, encKey, newLastmdjson)
	mdnewLastEnt.Enctxt = ciphertxt
	mdnewLastEnt.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	mdnewLastEntJson, _ := json.Marshal(mdnewLastEnt)
	userlib.DatastoreSet(newLastmdUUID, mdnewLastEntJson)

	mdLast.NextUUID = newLastmdUUID
	IV2 := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	updatedmdLastJson, _ := json.Marshal(mdLast)
	var updatedmdLastEnt DatastoreEntity
	ciphertxt = encry(IV2, encKey, updatedmdLastJson)
	updatedmdLastEnt.Enctxt = ciphertxt
	updatedmdLastEnt.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	updatedmdLastEntJson, _ := json.Marshal(updatedmdLastEnt)
	userlib.DatastoreSet(mdLast.FileUUID, updatedmdLastEntJson)

	return newLastmdUUID, nil
}

func updateFirstMetadata(metaEntity MetaDataStore, newLastUUID uuid.UUID, encKey, hmacKey []byte, metaUUID uuid.UUID) error {
	metaEntity.LastUUID = newLastUUID
	metaEntity.TotalBlocks += 1
	IV3 := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	mdjson, _ := json.Marshal(metaEntity)
	var metaDataEntity DatastoreEntity
	ciphertxt := encry(IV3, encKey, mdjson)
	metaDataEntity.Enctxt = ciphertxt
	metaDataEntity.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	mdEntityjson, _ := json.Marshal(metaDataEntity)
	userlib.DatastoreSet(metaUUID, mdEntityjson)
	return nil
}
func getShareTree(shareTreeID uuid.UUID) (Node, error) {
	shareTreeJson, ok := userlib.DatastoreGet(shareTreeID)
	if !ok {
		return Node{}, errors.New("getShareTree: fail to get share tree from ds")
	}

	var rootNode Node
	json.Unmarshal(shareTreeJson, &rootNode)
	return rootNode, nil
}

func findParents(rootNode Node, recipientUsername string) ([]Node, error) {
	var parentList []Node
	queue := []Node{rootNode}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if node.Username == recipientUsername {
			parentList = append(parentList, getParent(node.Parent))
		}

		for _, childID := range node.Children {
			childNode, _ := getNode(childID)
			queue = append(queue, childNode)
		}
	}

	if len(parentList) == 0 {
		return nil, errors.New("findParents: username not found in sharetree")
	}

	return parentList, nil
}

func deleteChildFromParents(parentList []Node, recipientUsername string) error {
	for _, parentNode := range parentList {
		delete(parentNode.Children, recipientUsername)
		parentNodeJson, _ := json.Marshal(parentNode)
		userlib.DatastoreSet(parentNode.Nodeid, parentNodeJson)
	}
	return nil
}

func getParent(parentID uuid.UUID) Node {
	parentJson, _ := userlib.DatastoreGet(parentID)
	var parentNode Node
	json.Unmarshal(parentJson, &parentNode)
	return parentNode
}

func getNode(nodeID uuid.UUID) (Node, error) {
	nodeJson, ok := userlib.DatastoreGet(nodeID)
	if !ok {
		return Node{}, errors.New("getNode: fail to get node from ds")
	}

	var node Node
	json.Unmarshal(nodeJson, &node)
	return node, nil
}

/*User functions*/

// InitUser creates a new user with the given username and password.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// if name already exists, return error
	usermapuuid, _ := uuid.FromBytes([]byte("map"))
	userCheck := userlib.Argon2Key([]byte(username), []byte("foo"), 16)
	usermapjson, ok := userlib.DatastoreGet(usermapuuid)
	UserMapEnt := make(map[uuid.UUID]bool)

	if !ok {
		store, _ := uuid.FromBytes(userCheck)
		UserMapEnt[store] = true
	} else {
		if err := json.Unmarshal(usermapjson, &UserMapEnt); err != nil {
			return nil, errors.New("InitUser: Cannot unmarshal json")
		}
		store, _ := uuid.FromBytes(userCheck)
		_, ok2 := UserMapEnt[store]

		if ok2 {
			return nil, errors.New("InitUser: User already exists")
		} else {
			UserMapEnt[store] = true
		}
	}

	userdata.Username = username

	// Argon2 hash generation for user and password
	userdata.PWHash = userlib.Argon2Key([]byte(username), []byte(password), 32)
	userdata.UserUUID, _ = uuid.FromBytes(userdata.PWHash[:16])

	// Argon2 deterministic keys generation for HMAC and encryption
	bytesUserNamePassword := append([]byte(username), []byte(password)...)
	userdata.EncKey = userlib.Argon2Key(bytesUserNamePassword, []byte("encryption"), userlib.AESKeySizeBytes)
	userdata.HMACKey = userlib.Argon2Key(bytesUserNamePassword, []byte("hmacdcddce"), userlib.AESKeySizeBytes)

	// Key generation and store for encryption
	var encKey userlib.PKEEncKey
	encKey, userdata.DecKey, _ = userlib.PKEKeyGen()
	userlib.KeystoreSet(userdata.Username+"eKey", encKey)

	// Signature keys generation and storage
	var signKey userlib.DSSignKey
	var veriKey userlib.DSVerifyKey
	signKey, veriKey, _ = userlib.DSKeyGen()
	userlib.KeystoreSet(userdata.Username+"vKey", veriKey)
	userdata.SignKey = signKey

	// Map initialization
	userdata.FilesUUID = make(map[string]uuid.UUID)
	userdata.Token = make(map[string]uuid.UUID)
	userdata.FilesEnc = make(map[string][]byte)
	userdata.FilesHMAC = make(map[string][]byte)
	userdata.Sessions = make(map[uuid.UUID]*Session)
	userdata.ValidTokens = make(map[string]bool)

	// Create a new session for this user
	//session, err := userdata.newSession()
	if err != nil {
		// Handle error
		return nil, err
	}
	// User data marshalling
	userToJSON, _ := json.Marshal(userdata)

	// Applying encryption and HMAC signing
	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	var userEntInstance DatastoreEntity
	userEntInstance.Enctxt = encry(IV, userdata.EncKey, userToJSON)
	userEntInstance.HMACSignedtxt, _ = hmacSigner(userdata.HMACKey, userEntInstance.Enctxt)

	entityToJSON, _ := json.Marshal(userEntInstance)

	// Store user data
	userlib.DatastoreSet(userdata.UserUUID, entityToJSON)

	return &userdata, nil
}

func GetUser(username string, password string) (userPtr *User, err error) {
	// Generate user UUID from username and password
	key := userlib.Argon2Key([]byte(username), []byte(password), 32)
	uuid, _ := uuid.FromBytes(key[:16])

	// Fetch user data
	storedData, exists := userlib.DatastoreGet(uuid)
	if !exists {
		return nil, errors.New("user not found")
	}

	// Parse stored data
	var storedUser DatastoreEntity
	err = json.Unmarshal(storedData, &storedUser)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	// Validate HMAC signature
	encryptionKey, hmacKey := getEncryKeys([]byte(username), []byte(password))
	valid, _ := hmacverifier(hmacKey, storedUser.Enctxt, storedUser.HMACSignedtxt)
	if !valid {
		return nil, errors.New("HMAC validation failed")
	}

	// Decrypt and parse user data
	decrypted := decry(storedUser.Enctxt, encryptionKey)
	var user User
	err = json.Unmarshal(decrypted, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted user data: %w", err)
	}

	// Check for username consistency
	if user.Username != username {
		return nil, errors.New("username mismatch")
	}

	return &user, nil
}

func (user *User) StoreFile(filename string, data []byte) (err error) {
	// Get the current UUID of the file, if it exists
	currentUUID, exists := user.FilesUUID[filename]

	var metaUUID, fileUUID uuid.UUID
	var encryptionKey, hmacKey []byte

	if exists {
		metaUUID = currentUUID
		// Retrieve file UUID for reuse
		metaEntityJSON, _ := userlib.DatastoreGet(metaUUID)

		var metadataEntity DatastoreEntity
		json.Unmarshal(metaEntityJSON, &metadataEntity)

		hmacKey = user.FilesHMAC[filename]
		encryptionKey = user.FilesEnc[filename]

		validHMAC, _ := hmacverifier(hmacKey, metadataEntity.Enctxt, metadataEntity.HMACSignedtxt)
		if !validHMAC {
			return errors.New("StoreFile: Metadata HMAC validation failed")
		}

		metadataDecrypted := decry(metadataEntity.Enctxt, encryptionKey)
		var metadataDecryptedEntity MetaDataStore
		json.Unmarshal(metadataDecrypted, &metadataDecryptedEntity)
		fileUUID = metadataDecryptedEntity.FileUUID
	} else {
		// New UUIDs for meta and file
		metaUUID, fileUUID = uuid.New(), uuid.New()

		// Generate random encryption and HMAC keys
		encryptionKey = userlib.RandomBytes(userlib.AESKeySizeBytes)
		hmacKey = userlib.RandomBytes(userlib.AESKeySizeBytes)
	}

	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)

	// Encrypt and HMAC sign the file data
	var fileEntity DatastoreEntity
	fileEntity.Enctxt = encry(IV, encryptionKey, data)
	fileEntity.HMACSignedtxt, err = hmacSigner(hmacKey, fileEntity.Enctxt)
	if err != nil {
		return fmt.Errorf("StoreFile: Failed to sign with HMAC: %w", err)
	}

	entityJSON, _ := json.Marshal(&fileEntity)
	userlib.DatastoreSet(fileUUID, entityJSON)

	if !exists {
		// Add metadata
		var metadata MetaDataStore
		metadata.FileUUID = fileUUID
		metadata.LastUUID = metaUUID // last uuid is self
		metadata.TotalBlocks = 1

		// Encrypt and sign metadata
		metadataJSON, _ := json.Marshal(metadata)
		var metadataEntity DatastoreEntity
		IVForMeta := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		metadataEntity.Enctxt = encry(IVForMeta, encryptionKey, metadataJSON)
		metadataEntity.HMACSignedtxt, _ = hmacSigner(hmacKey, metadataEntity.Enctxt)

		// Store the metadata
		metadataEntityJSON, _ := json.Marshal(metadataEntity)
		userlib.DatastoreSet(metaUUID, metadataEntityJSON)

		// Update keys in user struct
		user.FilesEnc[filename] = encryptionKey
		user.FilesHMAC[filename] = hmacKey
		user.FilesUUID[filename] = metaUUID

		// Create root node for share tree
		var rootNode Node
		rootNode.Username = user.Username
		rootNode.Children = make(map[string]uuid.UUID)
		rootUUID := uuid.New()
		rootNode.Nodeid = rootUUID
		rootNodeJSON, _ := json.Marshal(rootNode)
		userlib.DatastoreSet(rootUUID, rootNodeJSON)

		user.Token[filename] = rootUUID

		// Update user in datastore
		userJSON, _ := json.Marshal(user)
		IVForUser := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		var userEntity DatastoreEntity
		userEntity.Enctxt = encry(IVForUser, user.EncKey, userJSON)
		userEntity.HMACSignedtxt, _ = hmacSigner(user.HMACKey, userEntity.Enctxt)

		userEntityJSON, _ := json.Marshal(userEntity)
		userlib.DatastoreSet(user.UserUUID, userEntityJSON)
	}

	return
}

func (userdata *User) AppendToFile(filename string, data []byte) (err error) {

	// scale linearly only with
	// the size of data being appended: encrypt only the new part of the file
	// and the number of users the file is shared with: BFS search on tree
	// user has no access to file
	filemdID, isOwned := userdata.FilesUUID[filename]
	shareTreeID, isShared := userdata.Token[filename]
	if !isOwned && !isShared {
		return errors.New("AppendToFile: the user has no access to the file")
	}

	// things needed for append
	var metaUUID uuid.UUID
	var encKey []byte
	var hmacKey []byte
	//var fileUUID uuid.UUID
	//var fileData []byte
	//var fileDataJson []byte

	// if owned
	if !isOwned && isShared {
		var userNode Node
		shareTreeJson, ok := userlib.DatastoreGet(shareTreeID)
		if !ok {
			return errors.New("AppendToFile: fail to get share tree from ds")
		}
		var rootNode Node
		json.Unmarshal(shareTreeJson, &rootNode)

		// BFS search on tree
		queue := make([]Node, 0)
		queue = append(queue, rootNode)
		for len(queue) > 0 {
			next := queue[0]
			queue = queue[1:]
			if next.Username == userdata.Username {
				userNode = next
				break
			}
			if len(next.Children) > 0 {
				for _, child := range next.Children {
					childJson, _ := userlib.DatastoreGet(child)
					var childNode Node
					json.Unmarshal(childJson, &childNode)
					queue = append(queue, childNode)
				}
			}
		}

		if len(userNode.Username) == 0 {
			return errors.New("AppendToFile: username not found in sharetree")
		}

		// decrypt record with RSA private key
		encRecord := userNode.FileKey
		decRecordbyte, err := userlib.PKEDec(userdata.DecKey, encRecord)
		var decRecord ShareRecord
		json.Unmarshal(decRecordbyte, &decRecord)
		if err != nil {
			return errors.New("AppendToFile: cannot decrypt node in sharetree")
		}

		// retrieve metadata UUID and file keys from the shareRecord struct
		metaUUID = decRecord.FileMdUUID
		encKey = decRecord.EncKey
		hmacKey = decRecord.HMACKey

	} else if isOwned {
		metaUUID = filemdID
		encKey = userdata.FilesEnc[filename]
		hmacKey = userdata.FilesHMAC[filename]
	}

	fileuuid := uuid.New()

	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)

	// store file entity for the new part
	var filedataEntity DatastoreEntity
	ciphertxt := encry(IV, encKey, data)
	filedataEntity.Enctxt = ciphertxt
	filedataEntity.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	entityJSON, _ := json.Marshal(filedataEntity)
	userlib.DatastoreSet(fileuuid, entityJSON)

	// retrieve the first metadata
	marshaledMdEntity, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		return errors.New("AppendToFile: fail to get first file metadata from ds")
	}
	var metaEntity DatastoreEntity // metadata entity
	json.Unmarshal(marshaledMdEntity, &metaEntity)
	hmac, _ := hmacverifier(hmacKey, metaEntity.Enctxt, metaEntity.HMACSignedtxt)
	if !hmac {
		return errors.New("AppendToFile: first metadata hmac fail")
	}
	metadataJson := decry(metaEntity.Enctxt, encKey)
	var metadataDec MetaDataStore
	json.Unmarshal(metadataJson, &metadataDec)

	// retrieve the last metadata
	lastUUID := metadataDec.LastUUID
	mdLastEntityJson, ok := userlib.DatastoreGet(lastUUID)
	if !ok {
		return errors.New("AppendToFile: fail to get last file metadata from ds")
	}
	var mdEntLast DatastoreEntity
	json.Unmarshal(mdLastEntityJson, &mdEntLast)
	hmac, _ = hmacverifier(hmacKey, mdEntLast.Enctxt, mdEntLast.HMACSignedtxt)
	if !hmac {
		return errors.New("AppendToFile: last metadata hmac fail")
	}
	mdLastJson := decry(mdEntLast.Enctxt, encKey)
	var mdLast MetaDataStore
	json.Unmarshal(mdLastJson, &mdLast)

	// if the last metadata is full, create a new metadata
	var newLastmd MetaDataStore
	newLastmd.FileUUID = fileuuid
	newLastmdUUID := uuid.New() // new metadata UUID

	// if the last metadata is not full, append to the last metadata
	newLastmdjson, _ := json.Marshal(newLastmd)
	var mdnewLastEnt DatastoreEntity
	IV1 := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphertxt = encry(IV1, encKey, newLastmdjson)
	mdnewLastEnt.Enctxt = ciphertxt
	mdnewLastEnt.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	mdnewLastEntJson, _ := json.Marshal(mdnewLastEnt)
	userlib.DatastoreSet(newLastmdUUID, mdnewLastEntJson)

	mdLast.NextUUID = newLastmdUUID

	updatedmdLastJson, _ := json.Marshal(mdLast)
	var updatedmdLastEnt DatastoreEntity
	IV2 := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphertxt = encry(IV2, encKey, updatedmdLastJson)
	updatedmdLastEnt.Enctxt = ciphertxt
	updatedmdLastEnt.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)
	updatedmdLastEntJson, _ := json.Marshal(updatedmdLastEnt)
	userlib.DatastoreSet(lastUUID, updatedmdLastEntJson)

	if metadataDec.TotalBlocks == 1 {
		metadataDec.NextUUID = newLastmdUUID
	}
	metadataDec.LastUUID = newLastmdUUID
	metadataDec.TotalBlocks = metadataDec.TotalBlocks + 1
	mdjson, _ := json.Marshal(metadataDec)
	var metaDataEntity DatastoreEntity
	IV3 := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphertxt = encry(IV3, encKey, mdjson)
	metaDataEntity.Enctxt = ciphertxt
	metaDataEntity.HMACSignedtxt, _ = hmacSigner(hmacKey, ciphertxt)

	mdEntityjson, _ := json.Marshal(metaDataEntity)
	userlib.DatastoreSet(metaUUID, mdEntityjson)

	return nil
}

// getDataEntity retrieves and decrypts a DsEntity from the datastore

func getDataEntity(uuid uuid.UUID, encKey []byte, hmacKey []byte) (DatastoreEntity, error) {
	marshaledData, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return DatastoreEntity{}, errors.New("datastore retrieval failed")
	}

	var dsEntity DatastoreEntity
	err := json.Unmarshal(marshaledData, &dsEntity)
	if err != nil {
		return DatastoreEntity{}, err
	}

	// Verify HMAC
	hmac, _ := hmacverifier(hmacKey, dsEntity.Enctxt, dsEntity.HMACSignedtxt)
	if !hmac {
		return DatastoreEntity{}, errors.New("HMAC verification failed")
	}

	return dsEntity, nil
}

func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	filemdID, isOwned := userdata.FilesUUID[filename]
	shareTreeID, isShared := userdata.Token[filename]

	// user has no access to the file
	if !isOwned && !isShared {
		return nil, errors.New("LoadFile: the user has no access to the file")
	}

	// things needed for load
	var metaUUID uuid.UUID
	var encKey []byte
	var hmacKey []byte

	// get uuid from sharetree if user does not own
	if !isOwned && isShared {
		var userNode Node

		shareTreeJson, ok := userlib.DatastoreGet(shareTreeID)
		if !ok {
			return nil, errors.New("LoadFile: fail to get share tree from ds")
		}

		var rootNode Node
		json.Unmarshal(shareTreeJson, &rootNode)

		// BFS search on tree
		queue := make([]Node, 0)
		queue = append(queue, rootNode)
		for len(queue) > 0 {
			next := queue[0]
			queue = queue[1:]
			if next.Username == userdata.Username {
				userNode = next
				break
			}
			if len(next.Children) > 0 {
				for _, child := range next.Children {
					childJson, _ := userlib.DatastoreGet(child)
					var childNode Node
					json.Unmarshal(childJson, &childNode)
					queue = append(queue, childNode)
				}
			}
		}

		// user has no access to file
		if len(userNode.Username) == 0 {
			return nil, errors.New("LoadFile: username not found in sharetree")
		}

		// decrypt record with RSA private key
		encRecord := userNode.FileKey
		decRecordbyte, err := userlib.PKEDec(userdata.DecKey, encRecord)
		var decRecord ShareRecord
		json.Unmarshal(decRecordbyte, &decRecord)
		if err != nil {
			return nil, errors.New("LoadFile: cannot decrypt node in sharetree")
		}

		// retrieve metadata UUID and file keys from the shareRecord struct
		metaUUID = decRecord.FileMdUUID
		encKey = decRecord.EncKey
		hmacKey = decRecord.HMACKey

	} else if isOwned {
		metaUUID = filemdID
		encKey = userdata.FilesEnc[filename]
		hmacKey = userdata.FilesHMAC[filename]
	}

	// retrieve first node
	marshaledMdEntity, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		return nil, errors.New("LoadFile: fail to get file metadata from ds")
	}
	var metaEntity DatastoreEntity
	json.Unmarshal(marshaledMdEntity, &metaEntity)
	hmac, _ := hmacverifier(hmacKey, metaEntity.Enctxt, metaEntity.HMACSignedtxt)
	if !hmac {
		return nil, errors.New("LoadFile: first metadata hmac fail")
	}
	metaEntJson := decry(metaEntity.Enctxt, encKey)
	var metaEntDec MetaDataStore
	json.Unmarshal(metaEntJson, &metaEntDec)

	// collect all file UUIDs
	var fileUUIDs []uuid.UUID
	nextUUID := metaEntDec.NextUUID
	currMD := metaEntDec
	for i := 0; i < metaEntDec.TotalBlocks; i++ {
		fileUUIDs = append(fileUUIDs, currMD.FileUUID)

		if i == metaEntDec.TotalBlocks-1 {
			break
		}
		// retrieve next metadata
		nextmdEntJson, ok := userlib.DatastoreGet(nextUUID)
		if !ok {
			return nil, errors.New("LoadFile: fail to get file metadata from ds")
		}
		var nextmdEnt DatastoreEntity
		json.Unmarshal(nextmdEntJson, &nextmdEnt)
		hmac, _ := hmacverifier(hmacKey, nextmdEnt.Enctxt, nextmdEnt.HMACSignedtxt)
		if !hmac {
			return nil, errors.New("LoadFile: subsequent metadata hmac fail")
		}
		nextmdJson := decry(nextmdEnt.Enctxt, encKey)
		var nextmd MetaDataStore
		json.Unmarshal(nextmdJson, &nextmd)

		// update next mdUUID and curr md
		nextUUID = nextmd.NextUUID
		currMD = nextmd
	}

	// collect all file data
	var filedata []byte

	for i := 0; i < len(fileUUIDs); i++ {
		filedataEntityJson, ok := userlib.DatastoreGet(fileUUIDs[i])
		if !ok {
			return nil, errors.New("LoadFile: missing file parts")
		}
		var filedataEntity DatastoreEntity
		json.Unmarshal(filedataEntityJson, &filedataEntity)
		hmac, _ := hmacverifier(hmacKey, filedataEntity.Enctxt, filedataEntity.HMACSignedtxt)

		if !hmac {
			return nil, errors.New("LoadFile: file hmac fail")
		}
		plaintxt := decry(filedataEntity.Enctxt, encKey)
		filedata = append(filedata, plaintxt...)
	}

	dataBytes = filedata
	return dataBytes, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	if recipientUsername == userdata.Username {
		return uuid.Nil, errors.New("CreateInvitation: User cannot invite themselves.")
	}

	fileUUID, fileOwnership := userdata.FilesUUID[filename]
	sharedTreeUUID, fileShared := userdata.Token[filename]

	if !fileOwnership && !fileShared {
		return uuid.Nil, errors.New("CreateInvitation: User does not have access to the file.")
	}

	var fileMetaUUID uuid.UUID
	var fileEncryptionKey []byte
	var fileHMACKey []byte

	var userNode Node
	//var userNodeUUID uuid.UUID
	var treeRootNode Node

	if fileShared {
		sharedTree, sharedTreeExists := userlib.DatastoreGet(sharedTreeUUID)
		if !sharedTreeExists {
			return uuid.Nil, errors.New("CreateInvitation: Failed to retrieve shared tree from datastore.")
		}
		json.Unmarshal(sharedTree, &treeRootNode)

		if fileOwnership {
			userNode = treeRootNode
			//userNodeUUID := treeRootNode.Nodeid
			fileMetaUUID = fileUUID
			fileEncryptionKey = userdata.FilesEnc[filename]
			fileHMACKey = userdata.FilesHMAC[filename]
		} else {
			queue := make([]Node, 0)
			queue = append(queue, treeRootNode)
			for len(queue) > 0 {
				nextNode := queue[0]
				queue = queue[1:]
				if nextNode.Username == userdata.Username {
					userNode = nextNode
					//userNodeUUID := nextNode.Nodeid
					break
				}
				if len(nextNode.Children) > 0 {
					for _, childUUID := range nextNode.Children {
						child, _ := userlib.DatastoreGet(childUUID)
						var childNode Node
						json.Unmarshal(child, &childNode)
						queue = append(queue, childNode)
					}
				}
			}
			if len(userNode.Username) == 0 {
				return uuid.Nil, errors.New("CreateInvitation: User not found in shared tree.")
			}

			encryptedFileKeys := userNode.FileKey
			decryptedFileKeys, err := userlib.PKEDec(userdata.DecKey, encryptedFileKeys)
			if err != nil {
				return uuid.Nil, errors.New("CreateInvitation: Cannot decrypt node in shared tree.")
			}
			var decryptedFileRecord ShareRecord
			json.Unmarshal(decryptedFileKeys, &decryptedFileRecord)

			fileMetaUUID = decryptedFileRecord.FileMdUUID
			fileEncryptionKey = decryptedFileRecord.EncKey
			fileHMACKey = decryptedFileRecord.HMACKey
		}
	} else if fileOwnership {
		fileMetaUUID = fileUUID
		fileEncryptionKey = userdata.FilesEnc[filename]
		fileHMACKey = userdata.FilesHMAC[filename]
	}

	var newShareRecord ShareRecord
	newShareRecord.EncKey = fileEncryptionKey
	newShareRecord.HMACKey = fileHMACKey
	newShareRecord.FileMdUUID = fileMetaUUID

	newShareRecordJSON, _ := json.Marshal(newShareRecord)
	recipientPublicKey, publicKeyExists := userlib.KeystoreGet(recipientUsername + "eKey")
	if !publicKeyExists {
		return uuid.Nil, errors.New("CreateInvitation: Recipient's public encryption key not found in keystore.")
	}
	encryptedShareRecord, _ := userlib.PKEEnc(recipientPublicKey, newShareRecordJSON)

	newToken := Token{
		Token: encryptedShareRecord,
		Sign:  nil,
	}

	userPrivateKey := userdata.SignKey
	signature, _ := userlib.DSSign(userPrivateKey, encryptedShareRecord)
	newToken.Sign = signature

	newTokenJSON, _ := json.Marshal(newToken)
	newTokenUUID := uuid.New()
	userlib.DatastoreSet(newTokenUUID, newTokenJSON)

	return newTokenUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {

	if senderUsername == userdata.Username {
		return errors.New("AcceptInvitation: A user cannot accept an invitation from themselves.")
	}

	fileIdentifier, owned := userdata.FilesUUID[filename]
	sharedTreeIdentifier, shared := userdata.Token[filename]

	if !owned && !shared {
		return errors.New("AcceptInvitation: This user doesn't have the rights to this file.")
	}

	var fileMetaData uuid.UUID
	var fileEncryptionKey []byte
	var fileHMACKey []byte

	var currentUserNode Node
	var currentUserNodeUUID uuid.UUID
	var rootNode Node

	if shared {
		sharedTreeData, exist := userlib.DatastoreGet(sharedTreeIdentifier)
		if !exist {
			return errors.New("AcceptInvitation: Could not fetch the shared tree from the datastore.")
		}
		json.Unmarshal(sharedTreeData, &rootNode)

		if owned {
			currentUserNode = rootNode
			currentUserNodeUUID = rootNode.Nodeid
			fileMetaData = fileIdentifier
			fileEncryptionKey = userdata.FilesEnc[filename]
			fileHMACKey = userdata.FilesHMAC[filename]
		} else {
			nodeList := make([]Node, 0)
			nodeList = append(nodeList, rootNode)
			for len(nodeList) > 0 {
				nextNode := nodeList[0]
				nodeList = nodeList[1:]
				if nextNode.Username == userdata.Username {
					currentUserNode = nextNode
					currentUserNodeUUID = nextNode.Nodeid
					break
				}
				if len(nextNode.Children) > 0 {
					for _, childUUID := range nextNode.Children {
						childData, _ := userlib.DatastoreGet(childUUID)
						var childNode Node
						json.Unmarshal(childData, &childNode)
						nodeList = append(nodeList, childNode)
					}
				}
			}

			if len(currentUserNode.Username) == 0 {
				return errors.New("AcceptInvitation: This user is not found in the shared tree.")
			}

			encryptedFileKeys := currentUserNode.FileKey
			decryptedFileKeys, err := userlib.PKEDec(userdata.DecKey, encryptedFileKeys)
			if err != nil {
				return errors.New("AcceptInvitation: Unable to decrypt the node in the shared tree.")
			}
			var decryptedFileRecord ShareRecord
			json.Unmarshal(decryptedFileKeys, &decryptedFileRecord)

			fileMetaData = decryptedFileRecord.FileMdUUID
			fileEncryptionKey = decryptedFileRecord.EncKey
			fileHMACKey = decryptedFileRecord.HMACKey
		}
	} else if owned {
		fileMetaData = fileIdentifier
		fileEncryptionKey = userdata.FilesEnc[filename]
		fileHMACKey = userdata.FilesHMAC[filename]
	}

	var newSharingRecord ShareRecord
	newSharingRecord.EncKey = fileEncryptionKey
	newSharingRecord.HMACKey = fileHMACKey
	newSharingRecord.FileMdUUID = fileMetaData

	newSharingRecordJSON, _ := json.Marshal(newSharingRecord)
	senderPublicKey, publicKeyExists := userlib.KeystoreGet(senderUsername + "vKey")
	if !publicKeyExists {
		return errors.New("AcceptInvitation: The sender's public key is not found in the keystore.")
	}
	encryptedSharingRecord, _ := userlib.PKEEnc(senderPublicKey, newSharingRecordJSON)

	var newNode Node
	newNode.Username = senderUsername
	newNode.FileKey = encryptedSharingRecord
	newNode.Parent = currentUserNodeUUID
	newNodeUUID := uuid.New()
	newNode.Nodeid = newNodeUUID

	if owned && shared {
		rootNode.Children[senderUsername] = newNodeUUID
		rootNodeUpdatedJSON, _ := json.Marshal(rootNode)
		userlib.DatastoreSet(sharedTreeIdentifier, rootNodeUpdatedJSON)
	} else if !owned && shared {
		if len(currentUserNode.Children) == 0 {
			currentUserNode.Children = make(map[string]uuid.UUID)
		}
		currentUserNode.Children[senderUsername] = newNodeUUID
		currentUserNodeUpdatedJSON, _ := json.Marshal(currentUserNode)
		userlib.DatastoreSet(currentUserNode.Nodeid, currentUserNodeUpdatedJSON)
	}

	newNodeJSON, _ := json.Marshal(newNode)
	userlib.DatastoreSet(newNodeUUID, newNodeJSON)

	updatedTreeUUID := userdata.Token[filename]

	var newShareToken Token
	updatedTreeUUIDJSON, _ := json.Marshal(updatedTreeUUID)
	encryptedUpdatedTreeUUID, err1 := userlib.PKEEnc(senderPublicKey, updatedTreeUUIDJSON)
	if err1 != nil {
		return errors.New("AcceptInvitation: Unable to get the public key from the keystore.")
	}
	newShareToken.Token = encryptedUpdatedTreeUUID
	newShareTokenSignature, _ := userlib.DSSign(userdata.SignKey, encryptedUpdatedTreeUUID)
	newShareToken.Sign = newShareTokenSignature

	newShareTokenUUID := uuid.New()
	newShareTokenJSON, _ := json.Marshal(newShareToken)
	userlib.DatastoreSet(newShareTokenUUID, newShareTokenJSON)

	userDataJSON, _ := json.Marshal(userdata)
	initializationVector := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	var encryptedUser DatastoreEntity
	ciphertext := encry(initializationVector, userdata.EncKey, userDataJSON)
	encryptedUser.Enctxt = ciphertext
	encryptedUser.HMACSignedtxt, _ = hmacSigner(userdata.HMACKey, ciphertext)
	encryptedUserDataJSON, _ := json.Marshal(encryptedUser)
	userlib.DatastoreSet(userdata.UserUUID, encryptedUserDataJSON)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if recipientUsername == userdata.Username {
		return errors.New("RevokeAccess: Cannot revoke access to yourself.")
	}

	// check if the user is the owner of the file
	shareTreeID, isOwned := userdata.FilesUUID[filename]
	if !isOwned {
		return errors.New("RevokeFile: not the owner of the file or file does not exist.")
	}

	// check if the file has been shared with others
	_, isShared := userdata.Token[filename]
	if !isShared {
		return errors.New("RevokeAccess: this file might not have been shared with anyone.")
	}

	// retrieve the share tree from the datastore
	rootNode, err := getShareTree(shareTreeID)
	if err != nil {
		return errors.New("RevokeAccess: fail to get share tree from ds")
	}

	// find the list of parents of the revoked user
	parentList, err := findParents(rootNode, recipientUsername)
	if err != nil {
		return errors.New("RevokeAccess: username not found in sharetree")
	}

	// remove the revoked user from their parents' children list
	err = deleteChildFromParents(parentList, recipientUsername)
	if err != nil {
		return err
	}

	return nil
}
