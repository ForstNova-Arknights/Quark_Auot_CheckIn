// 需要先设置环境变量：export USER_TOKEN="你的Bearer token"
const USER_TOKEN = process.env.USER_TOKEN;

if (!USER_TOKEN) {
  console.error('❌ USER_TOKEN 环境变量未设置');
  process.exit(0);
}

// FNV-1a + xorshift (完全照搬前端 Cap 的 f 函数)
function f(seed, len) {
  let hash = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  hash >>>= 0;
  let r = hash;
  let out = '';
  while (out.length < len) {
    r ^= r << 13;
    r ^= r >>> 17;
    r ^= r << 5;
    r >>>= 0;
    out += r.toString(16).padStart(8, '0');
  }
  return out.substring(0, len);
}

// 求解单个 challenge：暴力枚举 nonce
async function solveChallenge(saltHex, targetHex) {
  const encoder = new TextEncoder();
  const saltBytes = encoder.encode(saltHex);
  let nonce = 0;
  while (true) {
    const input = saltHex + nonce.toString();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(input));
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    if (hashHex.startsWith(targetHex)) {
      return nonce;
    }
    nonce++;
    if (nonce > 0xFFFFFFFF) throw new Error('No solution found');
  }
}

(async () => {
  try {
    // 1. 获取 challenge
    const chalResp = await fetch('https://captcha.mefrp.com/2bf50e050d/challenge', {
      method: 'POST',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/json',
        'Origin': 'https://www.mefrp.com',
        'Referer': 'https://www.mefrp.com/',
      },
    });
    const { challenge, token: chalToken } = await chalResp.json();
    const { c, s, d } = challenge;

    // 2. 生成 salt / target 列表
    const tasks = [];
    for (let i = 1; i <= c; i++) {
      const salt = f(chalToken + i, s);
      const target = f(chalToken + i + 'd', d);
      tasks.push({ salt, target });
    }

    // 3. 并发求解 PoW
    const solutions = await Promise.all(
      tasks.map(({ salt, target }) => solveChallenge(salt, target))
    );

    // 4. 提交 solutions 换取最终 captcha token
    const redeemResp = await fetch('https://captcha.mefrp.com/2bf50e050d/redeem', {
      method: 'POST',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/json',
        'Origin': 'https://www.mefrp.com',
        'Referer': 'https://www.mefrp.com/',
      },
      body: JSON.stringify({
        token: chalToken,
        solutions: solutions,
      }),
    });
    const redeemData = await redeemResp.json();
    if (!redeemData.success) {
      console.error('❌ redeem 失败:', redeemData);
      return;
    }
    const capToken = redeemData.token;

    // 5. 调用签到接口 — 注意这里使用反引号模板字符串，正确插入 USER_TOKEN
    const signResp = await fetch('https://api.mefrp.com/api/auth/user/sign', {
      method: 'POST',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${USER_TOKEN}`, 
        'Origin': 'https://www.mefrp.com',
        'Referer': 'https://www.mefrp.com/',
      },
      body: JSON.stringify({ captchaToken: capToken }),
    });
    if (!signResp.ok) {
      const errorText = await signResp.text();
      console.error(`签到请求失败 (${signResp.status}):`, errorText);
      process.exit(1);
    }
    const signData = await signResp.json();

    console.log('签到结果:', JSON.stringify(signData, null, 2));
  } catch (err) {
    console.error('运行出错:', err);
    process.exit(1);
  }
})();
