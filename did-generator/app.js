import express from "express";
import crypto from "crypto";
import { importJWK, exportJWK } from "jose";
import { importSPKI, importPKCS8 } from "jose/key/import";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

app.post("/generate-did", async (req, res) => {
  try {
    const domain = req.body.domain || "example.com";
    const path = req.body.path || "user/alice";

    const { privateKey, publicKey } = await generateRsaKeyPair();
    const did = generateDidWeb(domain, path);

    const publicJwk = await exportJWK(publicKey);

    const didDocument = generateDidDocument(did, publicJwk);

    const solidResponse = await uploadToSolid(didDocument, path);

    if (!solidResponse.ok) {
      const errorText = await solidResponse.text();
      return res
        .status(solidResponse.status)
        .json({ error: "Upload to Solid failed", details: errorText });
    }

    res.json({
      did,
      uploadedTo: solidResponse.headers.get("Location") || "unknown",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to generate and upload DID" });
  }
});

async function generateRsaKeyPair() {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      "rsa",
      {
        modulusLength: 2048,
        publicKeyEncoding: { format: "pem", type: "spki" },
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
      },
      async (err, pubPem, privPem) => {
        if (err) return reject(err);
        try {
          const publicKey = await importSPKI(pubPem, "RS256");
          const privateKey = await importPKCS8(privPem, "RS256");
          resolve({ publicKey, privateKey });
        } catch (e) {
          reject(e);
        }
      },
    );
  });
}

function generateDidWeb(domain, path = "") {
  const sanitizedDomain = domain.toLowerCase();
  const sanitizedPath = path
    .split("/")
    .map((part) => part.toLowerCase())
    .join(":");
  return sanitizedPath
    ? `did:web:${sanitizedDomain}:${sanitizedPath}`
    : `did:web:${sanitizedDomain}`;
}

function generateDidDocument(did, publicJwk) {
  const keyId = `${did}#rsa-key`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: publicJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
  };
}

async function uploadToSolid(didDocument, path) {
  const solidEndpoint = "http://solid:3000/my-pod/VerifiableCredentials/";

  const slug = `did-web-${path.replace(/\//g, "-")}`;

  const response = await fetch(solidEndpoint, {
    method: "POST",
    body: JSON.stringify(didDocument, null, 2),
    headers: {
      "Content-Type": "application/json",
      Slug: slug,
    },
  });

  return response;
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`DID generator running on port ${PORT}`));
