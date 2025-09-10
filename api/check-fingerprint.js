export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { visitorId } = req.body;

  try {
    const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
      headers: {
        "X-Master-Key": "$2a$10$iW0KV.c6R8xH/oZ1eERZUexce56LH30Jd0Ecra7b2LA4mZfZM4YHi",
      },
    });

    const json = await response.json();
    const bannedIds = json.record.bannedIds || [];

    const blocked = bannedIds.includes(visitorId);

    return res.status(200).json({ blocked });
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Server error" });
  }
}
