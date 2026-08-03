package machine

import "testing"

func TestRemoveExitedNodeRemovesCurrentHandle(t *testing.T) {
	handle := &nodeHandle{}
	o := &Orchestrator{nodes: map[int]*nodeHandle{183: handle}}

	o.removeExitedNode(183, handle)

	if _, ok := o.nodes[183]; ok {
		t.Fatal("exited node handle was not removed")
	}
}

func TestRemoveExitedNodeKeepsReplacementHandle(t *testing.T) {
	exited := &nodeHandle{}
	replacement := &nodeHandle{}
	o := &Orchestrator{nodes: map[int]*nodeHandle{183: replacement}}

	o.removeExitedNode(183, exited)

	if got := o.nodes[183]; got != replacement {
		t.Fatal("replacement node handle was removed")
	}
}
