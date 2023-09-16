package TokenSystem

import "testing"

func TestTokenSystem_CreateToken(t *testing.T) {
    ts := &TokenSystem{}
    ts.Salt = "hello world"
    masterKey, _ := ts.CreateMasterKey()
    t.Logf("master key: %v\n", masterKey)

    t.Logf("master key valid: %v\n", ts.CheckKey(masterKey))
    t.Logf("master key valid: %v\n", ts.CheckKey(masterKey+" "))

    nk1, _ := ts.CreateNodeToken(masterKey)
    nk2, _ := ts.CreateNodeToken(masterKey)

    t.Logf("node1 key: %v\n", nk1)
    t.Logf("node2 key: %v\n", nk2)

    t.Logf("node1 key valid: %v\n", ts.CheckKey(nk1))
    t.Logf("node2 key valid: %v\n", ts.CheckKey(nk2))
    t.Logf("node1 key valid: %v\n", ts.CheckKey(nk1+" "))
    t.Logf("node2 key valid: %v\n", ts.CheckKey(nk2+" "))
    if v1, v2, ok := ts.ParseKey(masterKey); ok {
        t.Logf("master key: %v %v", v1, v2)
    }
    if v1, v2, ok := ts.ParseKey(nk1); ok {
        t.Logf("node key: %v %v", v1, v2)
    }
}
