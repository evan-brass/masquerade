# Masquerade
A single-hop relay using the TURN wire format.

I run a free instance of this server.  Feel free to use it and see if it works for you.
```javascript
const config = {
	iceTransportPolicy: 'relay', // Force relaying because I want to show the TURN server in action.
	iceServers: [{
		urls: [
			'turn:stun.evan-brass.net',
			'turn:stun.evan-brass.net?transport=tcp',
		],
		username: 'guest',
		credential: 'password'
	}],
};

const a = new RTCPeerConnection(config);
const b = new RTCPeerConnection(config);
a.createDataChannel('');

// Log connection states
a.addEventListener('connectionstatechange', () => console.log('a', a.connectionState));
b.addEventListener('connectionstatechange', () => console.log('b', b.connectionState));

// Negotiate the connection
await a.setLocalDescription();
while (a.iceGatheringState != 'complete') await new Promise(res => a.addEventListener('icegatheringstatechange', res, {once: true}));
await b.setRemoteDescription(a.localDescription);
await b.setLocalDescription();
while (b.iceGatheringState != 'complete') await new Promise(res => b.addEventListener('icegatheringstatechange', res, {once: true}));
await a.setRemoteDescription(b.localDescription);
```
