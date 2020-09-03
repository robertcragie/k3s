package ice

import (
	"fmt"

	"github.com/pion/webrtc/v3"
)

// GatherICE gathers ICE candidates.
func GatherICE() ([]webrtc.ICECandidate, error) {
	credtype := webrtc.ICECredentialTypePassword
	opts := webrtc.ICEGatherOptions{
		//		ICEServers: []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
		ICEServers: []webrtc.ICEServer{{URLs: []string{"turn:52.15.70.193"}, Username: "user", Credential: "pass",
			CredentialType: credtype}},
	}

	gatherer, err := webrtc.NewAPI().NewICEGatherer(opts)
	if err != nil {
		return nil, err
	}

	if gatherer.State() != webrtc.ICEGathererStateNew {
		return nil, fmt.Errorf("expected gathering state new")
	}

	gatherFinished := make(chan struct{})
	gatherer.OnLocalCandidate(func(i *webrtc.ICECandidate) {
		if i == nil {
			close(gatherFinished)
		}
	})

	if err = gatherer.Gather(); err != nil {
		return nil, err
	}

	<-gatherFinished

	params, err := gatherer.GetLocalParameters()
	if err != nil {
		return nil, err
	}

	if len(params.UsernameFragment) == 0 ||
		len(params.Password) == 0 {
		return nil, fmt.Errorf("empty local username or password frag")
	}

	candidates, err := gatherer.GetLocalCandidates()
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("No candidates gathered")
	}
	gatherer.Close()
	return candidates, nil
}
