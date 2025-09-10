// api/check-fingerprint.js

export default function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }
  let bannedId = "1e2083759073075c8536e11124cda377";
  try {
    const { visitorId } = req.body;
    if (visitorId === bannedId) {
      res.status(200).json({ blocked: true });
    } else {
      res.status(200).json({ blocked: false });
    }
  } catch (e) {
    res.status(400).json({ error: "Bad request" });
  }
}
