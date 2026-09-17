const { expect } = require("chai");

describe("SecureXRegistry", function () {
  it("registers and returns only cryptographic proof", async function () {
    const Registry = await ethers.getContractFactory("SecureXRegistry");
    const registry = await Registry.deploy();
    await registry.waitForDeployment();
    const documentId = ethers.id("DOC-1001");
    const documentHash = ethers.id("ciphertext-sha256");
    const tx = await registry.registerProof(documentId, documentHash, "DOCUMENT_ENCRYPTED");
    await tx.wait();
    const proof = await registry.latestProof(documentId);
    expect(proof[0]).to.equal(documentHash);
    expect(await registry.proofCount(documentId)).to.equal(1n);
  });
});
