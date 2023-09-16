package TokenSystem

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "github.com/bwmarrin/snowflake"
    rand2 "math/rand"
    "strings"
)

type TokenSystem struct {
    Salt string
}

var (
    ErrInvalidKey = errors.New("invalid key")
)

func (ts *TokenSystem) CreateMasterKey() (string, error) {
    // 生成一个唯一的用户ID
    userID := generateSnowflakeID()

    // 创建一个与用户ID关联的令牌
    token := generateRand(4) + userID
    // 创建一个签名
    signature, err := createSignature(ts.Salt, token)
    if err != nil {
        return "", err
    }
    return token + "." + signature, nil
}
func (ts *TokenSystem) CreateNodeToken(masterKey string) (string, error) {
    parts := strings.Split(masterKey, ".")
    if len(parts) != 2 {
        return "", ErrInvalidKey
    }
    // 验证签名
    if !validToken(ts.Salt, parts[0], parts[1]) {
        return "", ErrInvalidKey
    }

    // 生成NodeKey
    token := parts[0] + "." + generateRand(4)
    // 创建一个签名
    signature, err := createSignature(ts.Salt, token)
    if err != nil {
        return "", err
    }
    return token + "." + signature, nil
}
func (ts *TokenSystem) CheckKey(key string) bool {
    parts := strings.Split(key, ".")
    switch len(parts) {
    case 2:
        return validToken(ts.Salt, parts[0], parts[1])
    case 3:
        return validToken(ts.Salt, parts[0]+"."+parts[1], parts[2])
    }
    return false
}
func (ts *TokenSystem) ParseKey(key string) (userId string, nodeId string, ok bool) {
    if ts.CheckKey(key) {
        parts := strings.Split(key, ".")
        switch len(parts) {
        case 2:
            return parts[0], "", true
        case 3:
            return parts[0], parts[1], true
        }
    }
    return "", "", false
}

// 初始化Snowflake节点
var node *snowflake.Node

func init() {
    _ = ReInit(1)
}
func ReInit(nodeId int64) error {
    var err error
    node, err = snowflake.NewNode(nodeId)
    if err != nil {
        return err
    }
    return nil
}

// 生成一个基于Snowflake的唯一ID
func generateSnowflakeID() string {
    return node.Generate().String()
}

// 生成一段随机值
func generateRand(n int) string {
    salt := make([]byte, n)
    if _, err := rand.Read(salt); err != nil {
        for i, _ := range salt {
            salt[i] = byte(rand2.Intn(255))
        }
        return hex.EncodeToString([]byte(fmt.Sprint(rand2.Int())))
    }
    return hex.EncodeToString(salt)
}

// 创建一个签名，这里我们简单地使用SHA哈希
func createSignature(salt string, token string) (string, error) {
    data := append([]byte(token), []byte(salt)...)
    hash := sha256.Sum256(data)
    signature := hex.EncodeToString(hash[:])
    return signature, nil
}

// 验证token的签名
func validToken(salt string, token string, expectedHash string) bool {
    data := append([]byte(token), []byte(salt)...)
    hash := sha256.Sum256(data)
    signature := hex.EncodeToString(hash[:])
    return signature == expectedHash
}
