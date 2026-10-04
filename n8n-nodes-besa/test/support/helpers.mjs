// Minimal fake of n8n's IExecuteFunctions -- just enough surface for
// Besa.prototype.execute to run outside a real n8n instance. This is the
// standard way n8n community nodes are unit-tested without booting n8n
// itself; everything BELOW this boundary (the actual BESA crypto/admission/
// receipt logic) is the real, bundled @dorigjo/besa library, not a mock.
export function createMockExecuteFunctions({ items = [{}], parameters = {}, credentials, node } = {}) {
	let continueOnFailFlag = false;

	return {
		getInputData() {
			return items;
		},
		getNodeParameter(name, _itemIndex) {
			if (!(name in parameters)) {
				throw new Error(`test harness: no mock value provided for parameter "${name}"`);
			}
			return parameters[name];
		},
		async getCredentials(_name) {
			if (!credentials) {
				throw new Error('test harness: no mock credentials provided');
			}
			return credentials;
		},
		continueOnFail() {
			return continueOnFailFlag;
		},
		setContinueOnFail(value) {
			continueOnFailFlag = value;
		},
		getNode() {
			return node ?? { id: 'test-node', name: 'Besa', type: 'besa', typeVersion: 1, position: [0, 0] };
		},
	};
}

export function assertNoSubstring(haystack, needle, label) {
	if (typeof haystack !== 'string') {
		haystack = JSON.stringify(haystack);
	}
	if (needle && haystack.includes(needle)) {
		throw new Error(`${label}: leaked secret substring found in output`);
	}
}
