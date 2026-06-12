const USER_TOKEN = process.env.USER_TOKEN;

if (!USER_TOKEN) {
  console.error('❌ USER_TOKEN 环境变量未设置');
  process.exit(0);
}
console.log(USER_TOKEN+1)
// 完全模拟前端 Cap 的 f 函数（FNV-1a + xorshift）
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

// 求解单个 challenge：返回满足条件的 nonce（整数）
async function solveChallenge(saltHex, targetHex) {
    // saltHex 已经是十六进制字符串，解码成字节用于 SHA-256
    const saltBytes = new TextEncoder().encode(saltHex);
    // targetHex 是十六进制字符串，比如 "abc" → 要匹配前 1.5 字节（12 bit）
    // 我们直接比较 hex 字符串的前缀即可
    let nonce = 0;
    while (true) {
        const input = saltHex + nonce.toString();
        const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
        const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        if (hashHex.startsWith(targetHex)) {
            return nonce;
        }
        nonce++;
        // 防止死循环（实际 2^32 足够）
        if (nonce > 0xFFFFFFFF) throw new Error('No solution found');
    }
}

export default {
    async fetch(request, env, ctx) {
        // 1. 获取 challenge
        const chalResp = await fetch('https://captcha.mefrp.com/2bf50e050d/challenge', {
            method: 'POST',
            headers: {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Connection": "keep-alive",
  "Accept": "*/*",
  "Accept-Encoding": "gzip, deflate",
  "Content-Type": "application/json",
  "Origin": "https://www.mefrp.com",
  "Referer": "https://www.mefrp.com/",
  "Content-Length": "0"
}
        });
        const { challenge, token: chalToken } = await chalResp.json();
        const { c, s, d } = challenge;

        // 2. 生成所有 salt 和 target 列表
        const tasks = [];
        for (let i = 1; i <= c; i++) {
            const salt = f(chalToken + i, s);
            const target = f(chalToken + i + 'd', d);
            tasks.push({ salt, target });
        }

        // 3. 并发求解所有 PoW（每个 challenge 独立）
        const solutions = await Promise.all(
            tasks.map(async ({ salt, target }) => {
                return await solveChallenge(salt, target);
            })
        );

        // 4. 提交 solutions 换取最终 token
        const redeemResp = await fetch('https://captcha.mefrp.com/2bf50e050d/redeem', {
            method: 'POST',
            headers: {
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0",
              "Connection": "keep-alive",
              "Accept": "*/*",
              "Accept-Encoding": "gzip, deflate, br, zstd",
              "Content-Type": "application/json",
              "sec-ch-ua-platform": "\"Windows\"",
              "sec-ch-ua": "\"Microsoft Edge\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"",
              "dnt": "1",
              "sec-ch-ua-mobile": "?0",
              "origin": "https://www.mefrp.com",
              "sec-fetch-site": "same-site",
              "sec-fetch-mode": "cors",
              "sec-fetch-dest": "empty",
              "referer": "https://www.mefrp.com/",
              "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
              "priority": "u=1, i"
              },
            body: JSON.stringify({
                token: chalToken,
                solutions: solutions
            })
        });
        const redeemData = await redeemResp.json();
        if (!redeemData.success) {
            return new Response(JSON.stringify({ error: 'redeem failed' }), { status: 400 });
        }
        const capToken = redeemData.token;   // 这就是最终可用的 token

        // 5. 调用签到接口（使用你抓包拿到的 authorization 和 capToken）
        const signResp = await fetch('https://api.mefrp.com/api/auth/user/sign', {
            method: 'POST',
            headers: {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0",
  "Connection": "keep-alive",
  "Accept": "application/json, text/plain, */*",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  "Content-Type": "application/json",
  "sec-ch-ua-platform": "\"Windows\"",
  "authorization": "Bearer ${USER_TOKEN}",
  "sec-ch-ua": "\"Microsoft Edge\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"",
  "sec-ch-ua-mobile": "?0",
  "dnt": "1",
  "origin": "https://www.mefrp.com",
  "sec-fetch-site": "same-site",
  "sec-fetch-mode": "cors",
  "sec-fetch-dest": "empty",
  "referer": "https://www.mefrp.com/",
  "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
  "priority": "u=1, i"
},
            body: JSON.stringify({ captchaToken: capToken })
        });
        const signData = await signResp.json();

        // 6. 返回结果
      console.log(JSON.stringify({ signData, capToken }))
        return new Response(JSON.stringify({ signData, capToken }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
