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

  const { visitorId, username, password, userId, source, checkDuplicate, action } = req.body;

  // Handle sto-> authentication
  if (action === 'authenticate' && userId && password) {
    try {
      // Get existing data
      const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
        headers: {
          "X-Master-Key": "$2a$10$iW0KV.c6R8xH/oZ1eERZUexce56LH30Jd0Ecra7b2LA4mZfZM4YHi",
        },
      });
      
      const json = await response.json();
      const data = json.record;
      
      // Initialize arrays if they don't exist
      if (!data.calculatorUsers) data.calculatorUsers = [];
      if (!data.bannedIds) data.bannedIds = [];
      
      // Find user with matching password
      const userWithPassword = data.calculatorUsers.find(user => user.password === password);
      
      if (!userWithPassword) {
        return res.status(200).json({ 
          authorized: false, 
          message: "Invalid credentials" 
        });
      }
      
      // Check if the userId matches the one registered with this password
      if (userWithPassword.userId === userId) {
        return res.status(200).json({ 
          authorized: true, 
          message: "Authentication successful",
          username: userWithPassword.username
        });
      } else {
        // Password matches but userId doesn't - ban both userIds and remove registered user
        const userIdsToban = [userId, userWithPassword.userId];
        
        // Add both userIds to banned list if not already there
        userIdsToban.forEach(id => {
          if (!data.bannedIds.includes(id)) {
            data.bannedIds.push(id);
          }
        });
        
        // Remove the registered user from calculatorUsers
        data.calculatorUsers = data.calculatorUsers.filter(user => user.userId !== userWithPassword.userId);
        
        // Log the security incident with EST NYC time
        if (!data.securityIncidents) data.securityIncidents = [];
        const estTime = new Date().toLocaleString("en-US", {
          timeZone: "America/New_York",
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        });
        
        data.securityIncidents.push({
          type: 'unauthorized_access_attempt',
          message: `${userWithPassword.username} / ${userWithPassword.userId} attempted to give password to ${userId}`,
          timestamp: estTime,
          action: 'both_users_banned_and_registered_user_deleted'
        });
        
        // Update the database
        await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-Master-Key": "$2a$10$iW0KV.c6R8xH/oZ1eERZUexce56LH30Jd0Ecra7b2LA4mZfZM4YHi",
          },
          body: JSON.stringify(data)
        });
        
        return res.status(200).json({ 
          authorized: false,
          banned: true,
          message: "Unauthorized access attempt detected." 
        });
      }
      
    } catch (error) {
      console.error("Error during authentication:", error);
      return res.status(500).json({ error: "Authentication failed" });
    }
  }

  // Handle calculator credentials registration
  if (username && password && userId) {
    try {
      // Get existing data
      const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
        headers: {
          "X-Master-Key": "$2a$10$iW0KV.c6R8xH/oZ1eERZUexce56LH30Jd0Ecra7b2LA4mZfZM4YHi",
        },
      });
      
      const json = await response.json();
      const data = json.record;
      
      // Initialize arrays if they don't exist
      if (!data.calculatorUsers) data.calculatorUsers = [];
      if (!data.bannedIds) data.bannedIds = [];
      
      // Check for duplicate password if requested
      if (checkDuplicate) {
        const passwordExists = data.calculatorUsers.some(user => user.password === password);
        if (passwordExists) {
          return res.status(400).json({ 
            error: "Password already exists", 
            message: "Please choose a different password" 
          });
        }
      }
      
      // Add new user data
      const newUser = {
        username,
        password,
        userId,
        timestamp: Date.now(),
        source: source || 'calculator'
      };
      
      data.calculatorUsers.push(newUser);
      
      // Update the database
      const updateResponse = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Master-Key": "$2a$10$iW0KV.c6R8xH/oZ1eERZUexce56LH30Jd0Ecra7b2LA4mZfZM4YHi",
        },
        body: JSON.stringify(data)
      });
      
      if (updateResponse.ok) {
        return res.status(200).json({ 
          success: true, 
          message: "Credentials saved",
          userId: userId
        });
      } else {
        throw new Error('Failed to update database');
      }
      
    } catch (error) {
      console.error("Error saving credentials:", error);
      return res.status(500).json({ error: "Failed to save credentials" });
    }
  }

  // Handle fingerprint checking
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

    // If not blocked, check for end part (custom fingerprint) matches
    if (!blocked && visitorId.includes('-')) {
      // Extract the custom fingerprint part (after the last dash)
      const customPart = visitorId.split('-').pop();

      // Check if any banned ID has the same custom fingerprint part
      blocked = bannedIds.some(bannedId => {
        if (bannedId.includes('-')) {
          const bannedCustomPart = bannedId.split('-').pop();
          return bannedCustomPart === customPart;
        }
        return false;
      });
    }

    if (blocked) {
      console.log(`Blocked access for ID: ${visitorId}`);
    }

    return res.status(200).json({ blocked });

  } catch (error) {
    console.error("Error checking fingerprint:", error);
    return res.status(500).json({ error: "Server error" });
  }
}
