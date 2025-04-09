const c = await Deno.connect({ transport: 'tcp', hostname: 'localhost', port: 3478 });
const reader = c.readable.getReader();

for (;;) {
	const { value, done } = await reader.read();
	console.log(value);
	if (done) break;
}
