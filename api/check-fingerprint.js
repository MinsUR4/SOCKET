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
  
  if (!visitorId) {
    return res.status(400).json({ error: "Missing visitorId" });
  }
  
  try {
    const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
      headers: {
        "X-Master-Key": "$2a$10$iW0KV.c6R8xH/oZ1eERZUexce56LH30Jd0Ecra7b2LA4mZfZM4YHi",
      },
    });
    
    const json = await response.json();
    const bannedIds = json.record.bannedIds || [];
    
    // Check for exact match first
    let blocked = bannedIds.includes(visitorId);
    
    // If not blocked, check for partial matches to handle format changes
    if (!blocked && visitorId.includes('-')) {
      // Extract the FingerprintJS part (before the first dash)
      const fpjsPart = visitorId.split('-')[0];
      
      // Check if the FingerprintJS part is banned
      blocked = bannedIds.some(bannedId => {
        // Check if banned ID matches the FingerprintJS part
        return bannedId === fpjsPart || bannedId.startsWith(fpjsPart + '-');
      });
    }
    
    // Optional: Log for monitoring (remove in production if not needed)
    if (blocked) {
      console.log(`Blocked access for ID: ${visitorId}`);
    }
    
    return res.status(200).json({ blocked });
    
  } catch (error) {
    console.error("Error checking fingerprint:", error);
    return res.status(500).json({ error: "Server error" });
  }
}

// Alternative: More robust partial matching function
function isIdBanned(visitorId, bannedIds) {
  // Direct match
  if (bannedIds.includes(visitorId)) {
    return true;
  }
  
  // If visitorId has enhanced format (contains dash)
  if (visitorId.includes('-')) {
    const fpjsPart = visitorId.split('-')[0];
    
    // Check if the base FingerprintJS ID is banned
    return bannedIds.some(bannedId => {
      // Exact match of base part
      if (bannedId === fpjsPart) return true;
      
      // Match base part of banned ID (if it also has enhanced format)
      if (bannedId.includes('-')) {
        const bannedFpjsPart = bannedId.split('-')[0];
        return bannedFpjsPart === fpjsPart;
      }
      
      return false;
    });
  }
  
  // For fallback IDs, only exact match
  return false;
}
