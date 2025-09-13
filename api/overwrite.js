import bcrypt from 'bcryptjs';

const ALLOWED_ORIGINS = [
  'http://ti-84-plus-ce-calculator-15409344.codehs.me',
  'https://ti-84-plus-ce-calculator-15409344.codehs.me'
];

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const ACCOUNT_LOCKOUT_TIME = 30 * 60 * 1000;
const failedAttempts = new Map();

function isRateLimited(identifier) {
  const now = Date.now();
  const attempts = rateLimitMap.get(identifier) || [];
  const recentAttempts = attempts.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (recentAttempts.length >= MAX_ATTEMPTS) {
    return true;
  }
  
  recentAttempts.push(now);
  rateLimitMap.set(identifier, recentAttempts);
  return false;
}

function isAccountLocked(userId) {
  const lockInfo = failedAttempts.get(userId);
  if (!lockInfo) return false;
  
  const now = Date.now();
  if (lockInfo.attempts >= 3 && now - lockInfo.lastAttempt < ACCOUNT_LOCKOUT_TIME) {
    return true;
  }
  
  if (now - lockInfo.lastAttempt >= ACCOUNT_LOCKOUT_TIME) {
    failedAttempts.delete(userId);
    return false;
  }
  
  return false;
}

function recordFailedAttempt(userId) {
  const now = Date.now();
  const current = failedAttempts.get(userId) || { attempts: 0, lastAttempt: 0 };
  
  if (now - current.lastAttempt > ACCOUNT_LOCKOUT_TIME) {
    current.attempts = 1;
  } else {
    current.attempts++;
  }
  
  current.lastAttempt = now;
  failedAttempts.set(userId, current);
}

export default async function handler(req, res) {
  const origin = req.headers.origin;
  
 if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", "null");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  if (isRateLimited(clientIP)) {
    return res.status(429).json({ error: "Too many requests" });
  }

  const { visitorId, username, password, userId, source, checkDuplicate, action } = req.body;

  if (action === 'authenticate' && userId && password) {
    if (isAccountLocked(userId)) {
      return res.status(429).json({ 
        authorized: false, 
        message: "Account temporarily locked due to failed attempts" 
      });
    }

    try {
      const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
        headers: {
          "X-Master-Key": process.env.JSONBIN_KEY,
        },
      });
      
      const json = await response.json();
      const data = json.record;
      
      if (!data.calculatorUsers) data.calculatorUsers = [];
      if (!data.bannedIds) data.bannedIds = [];
      
      const userWithHash = data.calculatorUsers.find(user => user.userId === userId);
      
      if (!userWithHash) {
        recordFailedAttempt(userId);
        return res.status(200).json({ 
          authorized: false, 
          message: "Invalid credentials" 
        });
      }
      
      const isPasswordValid = await bcrypt.compare(password, userWithHash.passwordHash);
      
      if (!isPasswordValid) {
        recordFailedAttempt(userId);
        return res.status(200).json({ 
          authorized: false, 
          message: "Invalid credentials" 
        });
      }
      
      failedAttempts.delete(userId);
      
      return res.status(200).json({ 
        authorized: true, 
        message: "Authentication successful",
        username: userWithHash.username
      });
      
    } catch (error) {
      console.error("Error during authentication:", error);
      return res.status(500).json({ error: "Authentication failed" });
    }
  }

  if (username && password && userId) {
    try {
      const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
        headers: {
          "X-Master-Key": process.env.JSONBIN_KEY,
        },
      });
      
      const json = await response.json();
      const data = json.record;
      
      if (!data.calculatorUsers) data.calculatorUsers = [];
      if (!data.bannedIds) data.bannedIds = [];
      
      if (checkDuplicate) {
        const userExists = data.calculatorUsers.some(user => user.userId === userId);
        if (userExists) {
          return res.status(400).json({ 
            error: "User already exists", 
            message: "User already registered" 
          });
        }
      }
      
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);
      
      const newUser = {
        username,
        passwordHash,
        userId,
        timestamp: Date.now(),
        source: source || 'calculator'
      };
      
      data.calculatorUsers.push(newUser);
      
      const updateResponse = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Master-Key": process.env.JSONBIN_KEY,
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

  if (!visitorId) {
    return res.status(400).json({ error: "Missing visitorId" });
  }

  try {
    const response = await fetch("https://api.jsonbin.io/v3/b/68c0ccc7d0ea881f40780fcf/latest", {
      headers: {
        "X-Master-Key": process.env.JSONBIN_KEY,
      },
    });

    const json = await response.json();
    const bannedIds = json.record.bannedIds || [];

    let blocked = bannedIds.includes(visitorId);

    if (!blocked && visitorId.includes('-')) {
      const customPart = visitorId.split('-').pop();

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
