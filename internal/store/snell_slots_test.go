package store

import "testing"

// Slots go lowest-free first, stay with their user, and a deleted user's slot is the
// next one handed out — so the port range stays as long as the user list.
func TestClaimSnellSlots(t *testing.T) {
	t.Parallel()
	st := newStore(t)
	var ids []int64
	for _, n := range []string{"a", "b", "c"} {
		u, err := st.CreateUser(n, "uuid-"+n, "pw", "tok-"+n, 0, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
	}
	got, err := st.ClaimSnellSlots(ids)
	if err != nil {
		t.Fatal(err)
	}
	if got[ids[0]] != 1 || got[ids[1]] != 2 || got[ids[2]] != 3 {
		t.Fatalf("first claim: %v", got)
	}
	// A second claim changes nothing.
	again, err := st.ClaimSnellSlots(ids)
	if err != nil || again[ids[1]] != 2 {
		t.Fatalf("second claim: %v %v", again, err)
	}
	if err := st.DeleteUser(ids[1]); err != nil {
		t.Fatal(err)
	}
	d, err := st.CreateUser("d", "uuid-d", "pw", "tok-d", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err = st.ClaimSnellSlots([]int64{d.ID, ids[1]})
	if err != nil {
		t.Fatal(err)
	}
	if got[d.ID] != 2 {
		t.Fatalf("the freed slot 2 went unused: %v", got)
	}
	if _, ok := got[ids[1]]; ok {
		t.Fatal("a deleted user got a slot")
	}
	if n, err := st.MaxSnellSlot(); err != nil || n != 3 {
		t.Fatalf("max slot %d (%v), want 3", n, err)
	}
	u, err := st.GetUser(d.ID)
	if err != nil || u.SnellSlot != 2 {
		t.Fatalf("stored slot: %+v %v", u, err)
	}
}
