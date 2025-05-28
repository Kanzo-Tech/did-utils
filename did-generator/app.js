import express from "express";
import crypto from "crypto";
import { exportJWK } from "jose";
import { importSPKI, importPKCS8 } from "jose/key/import";
import fetch from "node-fetch";
import { readFile } from "fs/promises";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const TOKEN_URL = process.env.TOKEN_URL;
const SIGN_API_URL = process.env.SIGN_API_URL;
const SOLID_ENDPOINT = process.env.SOLID_URL;

app.post("/generate-did", async (req, res) => {
  try {
    const domain = req.body.domain || "example.com";
    const path = req.body.path || "user/alice";

    // 1. Generar claves y DID
    const { privateKey, publicKey } = await generateRsaKeyPair();
    const did = generateDidWeb(domain, path);
    const publicJwk = await exportJWK(publicKey);
    const didDocument = generateDidDocument(did, publicJwk);

    // 2. Subir a Solid el DID Document
    const solidResponse = await uploadToSolid(didDocument, path);
    if (!solidResponse.ok) {
      const errorText = await solidResponse.text();
      return res
        .status(solidResponse.status)
        .json({ error: "Upload to Solid failed", details: errorText });
    }

    // 3. Leer PDF dummy local
    const pdfBuffer = await readFile("dummy.pdf");
    const pdfBase64 = pdfBuffer.toString("base64");

    // 4. Obtener token OAuth2
    const tokenResponse = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "client_credentials",
        scope: "openid",
      }),
    });
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      return res
        .status(500)
        .json({ error: "Failed to get auth token", details: errorText });
    }
    const { access_token: accessToken } = await tokenResponse.json();

    // 5. Preparar payload para firma
    const hash = crypto.createHash("sha1").update(pdfBuffer).digest("hex");
    const signPayload = {
      file: {
        content: pdfBase64,
        name: "dummy.pdf",
        type: "application/pdf",
        hash,
      },
      signers: [
        {
          profile: {
            dni: req.body.dni || "48948948-E",
            email: req.body.email || "prueba@rubricae.es",
            name: req.body.name || did,
          },
          sendEmailSignedDoc: false,
        },
      ],
    };

    // 6. Llamar API de firma
    const signResponse = await fetch(SIGN_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(signPayload),
    });
    if (!signResponse.ok) {
      const errorText = await signResponse.text();
      return res
        .status(signResponse.status)
        .json({ error: "Signing failed", details: errorText });
    }

    // 7. Obtener PDF firmado en base64
    const signedPdfBuffer = await signResponse.arrayBuffer();
    const signedPdfSlug = `signed-dummy-${path.replace(/\//g, "-")}.pdf`;

    // 8. Subir PDF firmado a Solid
    const signedUploadResponse = await fetch(SOLID_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/pdf",
        Slug: signedPdfSlug,
      },
      body: signedPdfBuffer,
    });
    if (!signedUploadResponse.ok) {
      const errorText = await signedUploadResponse.text();
      return res
        .status(signedUploadResponse.status)
        .json({ error: "Uploading signed PDF failed", details: errorText });
    }

    // 9. Responder con toda la info
    res.json({
      did,
      uploadedDidDocumentUrl:
        solidResponse.headers.get("Location") || "unknown",
      signedPdfUrl: signedUploadResponse.headers.get("Location") || "unknown",
    });
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ error: "Failed to generate, upload DID and sign/upload PDF" });
  }
});

async function generateRsaKeyPair() {
  return await new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      "rsa",
      {
        modulusLength: 2048,
        publicKeyEncoding: { format: "pem", type: "spki" },
        privateKeyEncoding: { format: "pem", type: "pkcs8" },
      },
      async (err, pubPem, privPem) => {
        if (err) return reject(err);
        const publicKey = await importSPKI(pubPem, "RS256");
        const privateKey = await importPKCS8(privPem, "RS256");
        resolve({ publicKey, privateKey });
      },
    );
  });
}

function generateDidWeb(domain, path = "") {
  const webId = path ? `${domain}:${path.replaceAll("/", ":")}` : domain;
  return `did:web:${webId}`;
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
  const slug = `did-web-${path.replace(/\//g, "-")}`;

  const response = await fetch(SOLID_ENDPOINT, {
    method: "POST",
    body: JSON.stringify(didDocument, null, 2),
    headers: {
      "Content-type": "text/plain",
      Slug: slug,
    },
  });

  return response;
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
