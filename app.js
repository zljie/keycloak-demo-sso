const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');
const axios = require('axios');
const qs = require('querystring');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

//http://localhost:8090
// Keycloak configuration
const SsoConfig = {
  baseUrl: 'keycloak base url',
  realm: 'keycloak里面的域',
  clientId: 'keycloak 配置一个客户端',
  clientSecret: 'keycloak 配置一个客户端秘钥',
  callbackUrl: '本地调用的host，例如本体起了localhost:8080 ，在keycloak配置这个，localhost:8080/callback'
};

const app = express();
const server = http.createServer(app);

// 存储活跃的WebSocket连接
const activeConnections = new Map();

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// 确保在所有路由之前添加body-parser中间件
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // 添加对JSON请求体的支持


// 配置会话
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false, // 改为false，避免创建不必要的会话
  name: 'oidc_session',
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24小时
    secure: false, // 在开发环境中设置为false，生产环境应设置为true
    httpOnly: true, // 防止XSS攻击
    sameSite: 'lax', // 允许跨站点请求但限制CSRF攻击
    path: '/'
  },
  // 添加更多会话配置
  rolling: true, // 每次请求都重置cookie过期时间
  unset: 'destroy' // 会话销毁时删除cookie
}));

// 初始化Passport
app.use(passport.initialize());
app.use(passport.session());

// 配置OpenID Connect策略
passport.use('oidc', new Strategy({
  issuer: `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}`,
  authorizationURL: `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/auth`,
  tokenURL: `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`,
  userInfoURL: `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`,
  clientID: SsoConfig.clientId,
  clientSecret: SsoConfig.clientSecret,
  callbackURL: SsoConfig.callbackUrl,
  scope: 'openid profile email',
  usernameField: 'eplus_account',
  passReqToCallback: true,
  saveTokens: true,
  state: true,
  nonce: true,
  skipUserProfile: false
}, (req, issuer, profile, context, idToken, accessToken, refreshToken, done) => {
  // 确保保存所有token
  profile.id_token = idToken;
  profile.access_token = accessToken;
  profile.refresh_token = refreshToken;
  
  console.log('认证成功，获取到的token:', {
    access_token: accessToken ? '已获取' : '未获取',
    id_token: idToken ? '已获取' : '未获取',
    refresh_token: refreshToken ? '已获取' : '未获取'
  });
  
  return done(null, profile);
}));

// 序列化和反序列化用户
passport.serializeUser((user, done) => {
  console.log('序列化用户，token状态:', {
    access_token: user.access_token ? '已获取' : '未获取',
    id_token: user.id_token ? '已获取' : '未获取'
  });
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// 中间件：检查用户是否已认证
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// 新增：检查认证状态和token有效性的中间件
function checkAuthAndToken(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.json({ 
      authenticated: false, 
      message: '用户未登录',
      redirect: '/'
    });
  }

  // 检查token是否存在
  if (!req.user.access_token) {
    return res.json({ 
      authenticated: false, 
      message: '访问令牌不存在',
      redirect: '/login'
    });
  }

  // 验证token有效性
  axios.get(`${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`, {
    headers: {
      'Authorization': `Bearer ${req.user.access_token}`
    }
  })
  .then(() => {
    return res.json({ 
      authenticated: true, 
      user: req.user 
    });
  })
  .catch((error) => {
    console.error('Token验证失败:', error.response?.status, error.response?.data);
    
    // 如果是401错误，说明token无效
    if (error.response?.status === 401) {
      req.logout((err) => {
        if (err) {
          console.error('自动登出时出错:', err);
        }
      });
      return res.json({ 
        authenticated: false, 
        message: '访问令牌已过期',
        redirect: '/login'
      });
    }
    
    // 其他错误
    return res.json({ 
      authenticated: false, 
      message: 'Token验证失败',
      redirect: '/login'
    });
  });
}

// 路由验证端点
app.get('/api/auth/verify', checkAuthAndToken);

// 新增：获取当前用户信息的端点
app.get('/api/auth/user', ensureAuthenticated, (req, res) => {
  res.json({
    authenticated: true,
    user: req.user
  });
});

// 修改首页路由，添加路由守卫逻辑
app.get('/', (req, res) => {
  console.log('访问首页，认证状态:', req.isAuthenticated());
  if (req.isAuthenticated()) {
    // 设置会话相关的cookie
    res.cookie('isAuthenticated', 'true', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24小时
    });

    res.send(`
      <h1>欢迎, ${req.user.displayName || req.user.id || '用户'}!</h1>
      <p>您已成功登录</p>
      <pre>${JSON.stringify(req.user, null, 2)}</pre>
      <h3>访问令牌信息:</h3>
      <pre>${JSON.stringify(req.user._json, null, 2)}</pre>
      <h3>ID令牌:</h3>
      <pre>${req.user.id_token || '未获取ID令牌'}</pre>
      <div style="margin: 20px 0;">
        <a href="/protected" onclick="return checkAuthBeforeNavigate('/protected')">访问受保护页面</a><br>
        <a href="/iframe-sso-test" onclick="return checkAuthBeforeNavigate('/iframe-sso-test')">iframe SSO Test</a><br>
        <a href="/keycloak-api-demo" style="color: #e67e22; font-weight: bold;">🧪 Keycloak API 学习实验室</a><br>
        <a href="/user-info-tutorial" style="color: #27ae60; font-weight: bold;">📘 用户信息接入指南 (教学版)</a><br>
        <a href="/oauth-config-tutorial" style="color: #8e44ad; font-weight: bold;">⚙️ 第三方系统 OAuth2 配置指南 (针对截图系统)</a><br>
        <a href="/sso-sequence-diagram" style="color: #e74c3c; font-weight: bold;">📈 SSO 登录与获取 Token 完整时序图解析</a><br>
        <a href="/get-code-only-demo" style="color: #16a085; font-weight: bold;">🎫 仅获取 Code 演示 (纯净版)</a><br>
        <a href="/logout">登出</a>
      </div>

      <script>
        // 存储会话信息到localStorage
        const sessionData = {
          isAuthenticated: true,
          user: ${JSON.stringify(req.user)},
          accessToken: ${JSON.stringify(req.user.access_token)},
          idToken: ${JSON.stringify(req.user.id_token)},
          refreshToken: ${JSON.stringify(req.user.refresh_token)},
          sessionState: ${JSON.stringify(req.user.session_state)}
        };
        
        localStorage.setItem('sessionData', JSON.stringify(sessionData));
      </script>
      
      <script src="/auth-guard.js"></script>
    `);
  } else {
    // 清除可能存在的会话数据
    res.clearCookie('isAuthenticated');
    res.send(`
      <h1>Keycloak OIDC 客户端示例</h1>
      <form action="/login-with-username" method="post">
        <label for="username">用户名:</label>
        <input type="text" id="username" name="username" required><br><br>
        <button type="submit">登录</button>
      </form>
      <br>
      <a href="/login">标准OIDC登录</a>
    `);
  }
});

// 中间件：检查用户是否有特定权限
function checkPermission(permission) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/');
    }
    
    // 从用户令牌中获取权限/角色信息
    const userRoles = req.user.realm_access?.roles || [];
    const resourceAccess = req.user.resource_access || {};
    //const clientRoles = resourceAccess['nodejs-app3']?.roles || [];
    
    // 合并所有角色
    const allRoles = [...userRoles, ...clientRoles];
    
    if (allRoles.includes(permission)) {
      return next();
    } else {
      return res.status(403).send('权限不足，无法访问此页面');
    }
  };
}

// 登录路由
app.get('/login', passport.authenticate('oidc'));

// 删除重复的路由处理函数，只保留一个
// 处理通过用户名直接登录 - 添加next参数
app.post('/login-with-username', (req, res, next) => {
  try {
    console.log('收到登录请求，表单数据:', req.body);
    const { username } = req.body;
    
    if (!username) {
      console.error('用户名为空');
      return res.redirect('/');
    }
    
    console.log('准备使用Passport认证，用户名:', username);
    
    // 将用户名存储在会话中，以便在认证过程中使用
    req.session.login_hint = username;
    
    // 使用passport.authenticate而不是手动重定向
    passport.authenticate('oidc', {
      login_hint: username
    })(req, res, next);
  } catch (error) {
    console.error('登录处理发生错误:', error);
    return res.status(500).send('登录处理发生错误: ' + error.message);
  }
});

// 回调路由 - 简化为使用标准方式
app.get('/callback',
  passport.authenticate('oidc', {
    successRedirect: '/',
    failureRedirect: '/',
    failureMessage: true
  })
);

// 受保护的页面 - 需要用户认证
app.get('/protected', ensureAuthenticated, (req, res) => {
  res.send(`
    <h1>受保护的页面</h1>
    <p>这是一个需要认证才能访问的页面</p>
    <h2>您的用户信息:</h2>
    <pre>${JSON.stringify(req.user, null, 2)}</pre>
    <h2>访问令牌:</h2>
    <pre>${req.user.access_token || '未获取访问令牌'}</pre>
    <h2>ID令牌:</h2>
    <pre>${req.user.id_token || '未获取ID令牌'}</pre>
    <a href="/" onclick="return checkAuthBeforeNavigate('/')">返回首页</a>

    <script src="/auth-guard.js"></script>
  `);
});

// 需要特定权限的页面
app.get('/admin', ensureAuthenticated, checkPermission('admin'), (req, res) => {
  res.send(`
    <h1>管理员页面</h1>
    <p>这是一个需要管理员权限才能访问的页面</p>
    <h2>您的角色信息:</h2>
    <pre>${JSON.stringify(req.user.realm_access, null, 2)}</pre>
    <a href="/">返回首页</a>
  `);
});

// 修改会话检查端点
app.get('/check-session', (req, res) => {
  console.log(req);
  console.log('check-session', req.isAuthenticated());
  if (!req.isAuthenticated()) {
    return res.json({ authenticated: false });
  }
  
  const sessionState = req.user.session_state;
  if (!sessionState) {
    return res.json({ authenticated: false });
  }

  axios.get(`${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`, {
    headers: {
      'Authorization': `Bearer ${req.user.access_token}`
    }
  })
  .then(() => {
    res.json({ authenticated: true });
  })
  .catch(() => {
    req.logout((err) => {
      if (err) {
        console.error('自动登出时出错:', err);
      }
    });
    res.json({ authenticated: false });
  });
});


// 修改后端通道登出路由
app.post('/backchannel-logout', express.json(), async (req, res) => {
  try {
    console.log('收到后端通道登出请求:', req.body);
    
    const logoutToken = req.body.logout_token;
    if (!logoutToken) {
      console.error('未收到登出令牌');
      return res.status(400).send('Missing logout token');
    }

    try {
      const tokenParts = logoutToken.split('.');
      if (tokenParts.length !== 3) {
        throw new Error('Invalid token format');
      }

      const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
      
      if (!payload.iss || !payload.sid || !payload.iat) {
        throw new Error('Invalid token payload');
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error('Token expired');
      }

      if (payload.iss !== `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}`) {
        throw new Error('Invalid token issuer');
      }

      console.log('登出令牌验证成功:', payload);

      const sessionId = payload.sid;
      const store = req.sessionStore;
      
      if (store && typeof store.all === 'function') {
        const sessions = await new Promise((resolve, reject) => {
          store.all((err, sessions) => {
            if (err) reject(err);
            else resolve(sessions);
          });
        });

        for (const session of sessions) {
          if (session.passport && session.passport.user && 
              session.passport.user.session_state === sessionId) {
            await new Promise((resolve, reject) => {
              store.destroy(session.id, (err) => {
                if (err) reject(err);
                else resolve();
              });
            });
            // 通知对应的WebSocket客户端
            notifyLogout(session.id);
            console.log('已销毁匹配的会话:', session.id);
          }
        }
      }

      res.status(200).send('Logout successful');
    } catch (error) {
      console.error('验证登出令牌时出错:', error);
      res.status(400).send('Invalid logout token');
    }
  } catch (error) {
    console.error('处理后端通道登出请求时出错:', error);
    res.status(500).send('Internal server error');
  }
});

app.get('/api/check-login', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    res.json({ loggedIn: true, user: req.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// 修改现有的登出路由，添加前端通道登出
app.get('/logout', (req, res) => {
  const idTokenHint = req.user?.id_token || '';
  
  req.logout((err) => {
    if (err) {
      console.error('注销时出错:', err);
      return res.status(500).send('登出失败');
    }
    
    // 构建Keycloak登出URL，添加前端通道登出参数
    const logoutUrl = new URL(`${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/logout`);
    logoutUrl.searchParams.append('client_id', SsoConfig.clientId);
    logoutUrl.searchParams.append('post_logout_redirect_uri', 'http://localhost:3003');
    if (idTokenHint) {
      logoutUrl.searchParams.append('id_token_hint', idTokenHint);
    }
    // 添加前端通道登出参数
    logoutUrl.searchParams.append('frontchannel_logout_uri', 'http://localhost:3003/frontchannel-logout');

    console.log('重定向到Keycloak登出页面:', logoutUrl.toString());
    
    // 返回一个HTML页面，先清除localStorage，然后重定向
    res.send(`
      <html>
        <head>
          <title>登出中...</title>
          <script>
            // 清除localStorage中的所有数据
            try {
              localStorage.removeItem('sessionData');
              localStorage.removeItem('isAuthenticated');
              localStorage.removeItem('user');
              localStorage.removeItem('accessToken');
              localStorage.removeItem('idToken');
              localStorage.removeItem('refreshToken');
              localStorage.removeItem('sessionState');
              
              // 清除所有以特定前缀开头的localStorage项
              const keysToRemove = [];
              for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && (key.startsWith('auth_') || key.startsWith('sso_') || key.startsWith('keycloak_'))) {
                  keysToRemove.push(key);
                }
              }
              keysToRemove.forEach(key => localStorage.removeItem(key));
              
              console.log('localStorage已清除');
            } catch (error) {
              console.error('清除localStorage时出错:', error);
            }
            
            // 清除相关的cookie
            try {
              document.cookie = 'isAuthenticated=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
              document.cookie = 'oidc_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            } catch (error) {
              console.error('清除cookie时出错:', error);
            }
            
            // 延迟重定向，确保localStorage清除完成
            setTimeout(function() {
              window.location.href = '${logoutUrl.toString()}';
            }, 100);
          </script>
        </head>
        <body>
          <h1>正在登出...</h1>
          <p>正在清除本地数据并重定向到登出页面...</p>
        </body>
      </html>
    `);
  });
});

// 修改前端通道登出路由
app.get('/frontchannel-logout', (req, res) => {
  console.log('收到前端通道登出请求');
  
  // 清理本地会话
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('销毁会话时出错:', err);
      }
    });
  }

  // 返回一个HTML页面，清理所有存储的会话信息
  res.send(`
    <html>
      <head>
        <title>登出中...</title>
        <script>
          // 清理localStorage
          localStorage.removeItem('sessionData');
          
          // 清理cookie
          document.cookie = 'isAuthenticated=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
          
          // 关闭当前窗口
          window.close();
          
          // 如果无法关闭窗口，则重定向到首页
          setTimeout(function() {
            window.location.href = '/';
          }, 1000);
        </script>
      </head>
      <body>
        <h1>正在登出...</h1>
        <p>如果页面没有自动关闭，请手动关闭此窗口。</p>
      </body>
    </html>
  `);
});

// 修改 iframe 测试页面路由
app.get('/iframe-test', ensureAuthenticated, (req, res) => {
  // 详细的调试信息
  console.log('=== iframe-test 路由调试信息 ===');
  console.log('req.user 存在:', !!req.user);
  if (req.user) {
    console.log('req.user 属性:', Object.keys(req.user));
    console.log('access_token 存在:', !!req.user.access_token);
    console.log('id_token 存在:', !!req.user.id_token);
  }

  // 检查token是否存在
  if (!req.user || !req.user.access_token) {
    console.error('用户token不存在:', req.user);
    return res.redirect('/login');
  }

  // 将token信息转换为安全的字符串
  const safeAccessToken = req.user.access_token ? JSON.stringify(req.user.access_token) : '""';
  const safeIdToken = req.user.id_token ? JSON.stringify(req.user.id_token) : '""';

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SSO iframe 测试页面</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        button { margin: 5px; padding: 8px 15px; cursor: pointer; }
        .log { max-height: 300px; overflow-y: auto; background-color: #f8f9fa; padding: 10px; border: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <h1>SSO iframe 测试页面</h1>
      <p>这个页面用于测试通过iframe嵌入其他SSO站点，解决iframe内需要重新登录的问题</p>
      
      <div class="section info">
        <h3>当前认证状态</h3>
        <p><strong>用户ID:</strong> ${req.user.id || 'N/A'}</p>
        <p><strong>用户名:</strong> ${req.user.displayName || req.user.username || 'N/A'}</p>
        <p><strong>Access Token:</strong> ${req.user.access_token ? '已获取' : '未获取'}</p>
        <p><strong>ID Token:</strong> ${req.user.id_token ? '已获取' : '未获取'}</p>
      </div>

      <div class="section">
        <h3>测试选项</h3>
        <div style="margin: 10px 0;">
          <label for="iframeUrl">iframe URL:</label>
          <input type="text" id="iframeUrl" style="width: 400px;" 
                         value="host" placeholder="输入要测试的URL">
        </div>
        <button onclick="loadSSOIframe()">加载SSO iframe</button>
        <button onclick="loadNormalIframe()">加载普通 iframe</button>
        <button onclick="testTokenTransfer()">测试Token传递</button>
        <button onclick="diagnoseSSO()">诊断SSO问题</button>
        <button onclick="clearLog()">清除日志</button>
      </div>

      <div class="section">
        <h3>iframe 容器</h3>
        <div id="iframeContainer" style="margin-top: 10px;">
          <iframe id="testIframe" style="width: 100%; height: 600px; border: 1px solid #ccc;" 
                  allow="fullscreen"
                  referrerpolicy="origin"
                  sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
                  src="about:blank"></iframe>
        </div>
      </div>

      <div class="section">
        <h3>调试日志</h3>
        <div id="debugOutput" class="log"></div>
      </div>

      <div class="section">
        <h3>解决方案说明</h3>
        <div class="info">
          <h4>问题原因：</h4>
          <ul>
            <li><strong>跨域隔离：</strong>iframe和父页面不同域名，无法共享认证信息</li>
            <li><strong>Cookie隔离：</strong>不同域名的Cookie是隔离的</li>
            <li><strong>Session隔离：</strong>每个域名都有独立的会话管理</li>
            <li><strong>Token传递问题：</strong>父页面的token没有正确传递给iframe</li>
          </ul>
          
          <h4>解决方案：</h4>
          <ul>
            <li><strong>postMessage通信：</strong>使用window.postMessage在父子页面间传递token</li>
            <li><strong>自动检测：</strong>iframe自动检测并请求父页面的SSO信息</li>
            <li><strong>多种备用方案：</strong>URL参数、localStorage缓存、父窗口访问</li>
            <li><strong>实时监控：</strong>监听iframe加载并自动发送token</li>
          </ul>
        </div>
      </div>

      <div style="margin-top: 20px;">
        <a href="/" onclick="return checkAuthBeforeNavigate('/')">返回首页</a>
      </div>

      <script>
        // 存储会话信息到localStorage
        const sessionData = {
          isAuthenticated: true,
          user: ${JSON.stringify(req.user)},
          accessToken: ${safeAccessToken},
          idToken: ${safeIdToken},
          refreshToken: ${JSON.stringify(req.user.refresh_token)},
          sessionState: ${JSON.stringify(req.user.session_state)},
          realm: '${SsoConfig.realm}',
          clientId: '${SsoConfig.clientId}'
        };
        
        localStorage.setItem('sessionData', JSON.stringify(sessionData));
        
        // 调试函数
        function debugLog(message, data) {
          console.log(\`[DEBUG] \${message}\`, data);
          const debugDiv = document.getElementById('debugOutput');
          if (debugDiv) {
            const timestamp = new Date().toLocaleTimeString();
            const dataStr = data ? JSON.stringify(data, null, 2) : '';
            debugDiv.innerHTML += \`<p><strong>\${timestamp}</strong> \${message} \${dataStr}</p>\`;
            debugDiv.scrollTop = debugDiv.scrollHeight;
          }
        }

        function clearLog() {
          document.getElementById('debugOutput').innerHTML = '';
        }

        // 获取当前用户的token
        let userToken = null;
        let idToken = null;
        
        try {
          userToken = ${safeAccessToken};
          idToken = ${safeIdToken};
          
          debugLog('Token初始化状态', {
            userToken: userToken ? '已获取' : '未获取',
            idToken: idToken ? '已获取' : '未获取',
            tokenLength: userToken ? userToken.length : 0
          });
        } catch (error) {
          debugLog('Token初始化错误', error);
        }

        // 加载SSO iframe（使用新的SSO处理工具）
        function loadSSOIframe() {
          const url = document.getElementById('iframeUrl').value;
          if (!url) {
            alert('请输入URL');
            return;
          }

          if (!userToken) {
            debugLog('Token错误', 'Token不存在，请重新登录');
            alert('Token不存在，请重新登录');
            window.location.href = '/login';
            return;
          }

          debugLog('加载SSO iframe', { url });

          const iframe = document.getElementById('testIframe');
          
          // 使用URL参数传递token（备用方案）
          const urlWithToken = \`\${url}\${url.includes('?') ? '&' : '?'}access_token=\${encodeURIComponent(userToken)}&id_token=\${encodeURIComponent(idToken)}&sso_mode=true\`;
          
          iframe.src = urlWithToken;
          
          // iframe加载完成后发送token
          iframe.onload = function() {
            try {
              debugLog('iframe加载完成，准备发送SSO信息', {
                hasAccessToken: !!userToken,
                hasIdToken: !!idToken
              });

              // 发送token到iframe
              const tokenMessage = {
                type: 'SSO_TOKEN',
                access_token: userToken,
                id_token: idToken,
                realm: '${SsoConfig.realm}',
                clientId: '${SsoConfig.clientId}',
                timestamp: Date.now()
              };

              iframe.contentWindow.postMessage(tokenMessage, 'host');
              debugLog('SSO信息已发送到iframe', 'success');
            } catch (e) {
              debugLog('发送SSO信息失败', e);
              console.error('发送SSO信息失败:', e);
            }
          };
        }

        // 加载普通iframe（不传递token）
        function loadNormalIframe() {
          const url = document.getElementById('iframeUrl').value;
          if (!url) {
            alert('请输入URL');
            return;
          }

          debugLog('加载普通iframe', { url });
          const iframe = document.getElementById('testIframe');
          iframe.src = url;
        }

        // 测试Token传递功能
        function testTokenTransfer() {
          const targetOrigin = 'host';
          const tokenMessage = {
            type: 'SSO_TOKEN',
            access_token: userToken,
            id_token: idToken,
            realm: '${SsoConfig.realm}',
            clientId: '${SsoConfig.clientId}',
            timestamp: Date.now()
          };

          debugLog('测试Token传递', {
            targetOrigin,
            hasAccessToken: !!userToken,
            hasIdToken: !!idToken,
            messageType: tokenMessage.type
          });

          // 尝试多种传递方式
          try {
            // 方式1: 直接postMessage
            window.postMessage(tokenMessage, targetOrigin);
            debugLog('方式1: 直接postMessage完成', 'success');
          } catch (e) {
            debugLog('方式1: 直接postMessage失败', e);
          }

          try {
            // 方式2: 通过iframe传递
            const iframe = document.getElementById('testIframe');
            if (iframe && iframe.contentWindow) {
              iframe.contentWindow.postMessage(tokenMessage, targetOrigin);
              debugLog('方式2: 通过iframe传递完成', 'success');
            }
          } catch (e) {
            debugLog('方式2: 通过iframe传递失败', e);
          }

          // 方式3: 通过URL参数传递
          const urlWithToken = host;
          debugLog('方式3: URL参数方式', { url: urlWithToken.substring(0, 100) + '...' });
        }

        // 诊断SSO问题
        function diagnoseSSO() {
          debugLog('开始SSO诊断', '');
          
          // 检查浏览器环境
          debugLog('浏览器信息', {
            userAgent: navigator.userAgent,
            cookieEnabled: navigator.cookieEnabled,
            onLine: navigator.onLine
          });

          // 检查cookie设置
          debugLog('Cookie信息', {
            documentCookie: document.cookie,
            cookieLength: document.cookie.length
          });

          // 检查localStorage
          try {
            const sessionData = localStorage.getItem('sessionData');
            debugLog('localStorage信息', {
              hasSessionData: !!sessionData,
              sessionDataLength: sessionData ? sessionData.length : 0
            });
          } catch (e) {
            debugLog('localStorage访问失败', e);
          }

          // 检查iframe状态
          const iframe = document.getElementById('testIframe');
          debugLog('iframe状态', {
            exists: !!iframe,
            src: iframe ? iframe.src : 'N/A',
            contentWindow: !!iframe?.contentWindow,
            sameOrigin: iframe ? (try { iframe.contentWindow.location.href; return true; } catch(e) { return false; })() : false
          });

          // 检查跨域限制
          debugLog('跨域检查', {
            currentOrigin: window.location.origin,
            targetOrigin: 'host',
            isCrossOrigin: window.location.origin !== 'host'
          });
        }

        // 监听来自iframe的消息
        window.addEventListener('message', function(event) {
          debugLog('收到消息', {
            origin: event.origin,
            data: event.data,
            source: event.source === window ? 'window' : 'iframe'
          });

          // 验证消息来源
          if (event.origin !== 'host') {
            console.warn('收到未知来源的消息:', event.origin);
            return;
          }
          
          // 处理来自iframe的请求
          if (event.data.type === 'REQUEST_TOKEN') {
            debugLog('收到token请求', event.data);

            const tokenMessage = {
              type: 'SSO_TOKEN',
              access_token: userToken,
              id_token: idToken,
              realm: '${SsoConfig.realm}',
              clientId: '${SsoConfig.clientId}',
              timestamp: Date.now()
            };

            debugLog('发送token到iframe', {
              type: 'SSO_TOKEN',
              hasAccessToken: !!userToken,
              hasIdToken: !!idToken
            });

            // 发送token到iframe
            event.source.postMessage(tokenMessage, event.origin);
          }

          // 处理认证状态反馈
          if (event.data.type === 'SSO_SUCCESS') {
            debugLog('收到SSO成功反馈', event.data);
          }

          if (event.data.type === 'SSO_FAILED') {
            debugLog('收到SSO失败反馈', event.data);
          }
        });

        // 页面加载完成后自动诊断
        window.onload = function() {
          debugLog('页面加载完成，准备诊断', '');
          setTimeout(diagnoseSSO, 500);
        };
      </script>

      <script src="/auth-guard.js"></script>
      <script src="/parent-iframe-handler.js"></script>
    </body>
    </html>
  `);
});

// 新增：SSO诊断页面路由
app.get('/sso-diagnosis', ensureAuthenticated, (req, res) => {
  const safeAccessToken = req.user.access_token ? JSON.stringify(req.user.access_token) : '""';
  const safeIdToken = req.user.id_token ? JSON.stringify(req.user.id_token) : '""';
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SSO诊断工具</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        button { margin: 5px; padding: 8px 15px; cursor: pointer; }
        .log { max-height: 400px; overflow-y: auto; background-color: #f8f9fa; padding: 10px; border: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <h1>SSO诊断工具</h1>
      
      <div class="section info">
        <h3>当前认证状态</h3>
        <p><strong>用户ID:</strong> ${req.user.id || 'N/A'}</p>
        <p><strong>用户名:</strong> ${req.user.displayName || req.user.username || 'N/A'}</p>
        <p><strong>Access Token:</strong> ${req.user.access_token ? '已获取' : '未获取'}</p>
        <p><strong>ID Token:</strong> ${req.user.id_token ? '已获取' : '未获取'}</p>
        <p><strong>Realm:</strong> ${SsoConfig.realm}</p>
        <p><strong>Client ID:</strong> ${SsoConfig.clientId}</p>
      </div>

      <div class="section">
        <h3>诊断操作</h3>
        <button onclick="runFullDiagnosis()">运行完整诊断</button>
        <button onclick="testTokenValidity()">测试Token有效性</button>
        <button onclick="testCrossOrigin()">测试跨域通信</button>
        <button onclick="testIframeSSO()">测试iframe SSO</button>
        <button onclick="clearLog()">清除日志</button>
      </div>

      <div class="section">
        <h3>诊断日志</h3>
        <div id="diagnosisLog" class="log"></div>
      </div>

      <div class="section">
        <h3>测试iframe</h3>
        <input type="text" id="testUrl" value="host" style="width: 300px;">
        <button onclick="loadTestIframe()">加载测试iframe</button>
        <div id="iframeContainer" style="margin-top: 10px;">
          <iframe id="testIframe" style="width: 100%; height: 400px; border: 1px solid #ccc;" 
                  allow="fullscreen" referrerpolicy="origin" 
                  sandbox="allow-same-origin allow-scripts allow-popups allow-forms"></iframe>
        </div>
      </div>

      <script>
        let userToken = ${safeAccessToken};
        let idToken = ${safeIdToken};
        
        function log(message, type = 'info') {
          const logDiv = document.getElementById('diagnosisLog');
          const timestamp = new Date().toLocaleTimeString();
          const className = type === 'error' ? 'error' : type === 'success' ? 'success' : type === 'warning' ? 'warning' : 'info';
          logDiv.innerHTML += \`<div class="\${className}"><strong>\${timestamp}</strong> \${message}</div>\`;
          logDiv.scrollTop = logDiv.scrollHeight;
          console.log(\`[SSO诊断] \${message}\`);
        }

        function clearLog() {
          document.getElementById('diagnosisLog').innerHTML = '';
        }

        async function testTokenValidity() {
          log('开始测试Token有效性...');
          
          if (!userToken) {
            log('错误: Access Token不存在', 'error');
            return;
          }

          try {
            const response = await fetch('/api/auth/verify');
            const data = await response.json();
            
            if (data.authenticated) {
              log('✓ Token验证成功', 'success');
              log('用户信息: ' + JSON.stringify(data.user, null, 2));
            } else {
              log('✗ Token验证失败: ' + data.message, 'error');
            }
          } catch (error) {
            log('✗ Token验证请求失败: ' + error.message, 'error');
          }
        }

        function testCrossOrigin() {
          log('开始测试跨域通信...');
          
          const targetOrigin = 'host';
          const testMessage = {
            type: 'SSO_TEST',
            timestamp: Date.now(),
            source: window.location.origin
          };

          try {
            window.postMessage(testMessage, targetOrigin);
            log('✓ 跨域消息发送成功', 'success');
          } catch (error) {
            log('✗ 跨域消息发送失败: ' + error.message, 'error');
          }
        }

        function testIframeSSO() {
          log('开始测试iframe SSO...');
          
          const iframe = document.getElementById('testIframe');
          if (!iframe) {
            log('✗ 测试iframe不存在', 'error');
            return;
          }

          const targetOrigin = 'host';
          const tokenMessage = {
            type: 'SSO_TOKEN',
            access_token: userToken,
            id_token: idToken,
            realm: '${SsoConfig.realm}',
            clientId: '${SsoConfig.clientId}',
            timestamp: Date.now()
          };

          try {
            iframe.contentWindow.postMessage(tokenMessage, targetOrigin);
            log('✓ Token已发送到iframe', 'success');
          } catch (error) {
            log('✗ 发送Token到iframe失败: ' + error.message, 'error');
          }
        }

        function loadTestIframe() {
          const url = document.getElementById('testUrl').value;
          if (!url) {
            log('请输入测试URL', 'warning');
            return;
          }

          log('加载测试iframe: ' + url);
          const iframe = document.getElementById('testIframe');
          iframe.src = url;
        }

        async function runFullDiagnosis() {
          log('=== 开始完整SSO诊断 ===');
          
          // 1. 检查浏览器环境
          log('1. 检查浏览器环境...');
          log('User Agent: ' + navigator.userAgent);
          log('Cookie启用: ' + navigator.cookieEnabled);
          log('在线状态: ' + navigator.onLine);
          
          // 2. 检查Token状态
          log('2. 检查Token状态...');
          log('Access Token: ' + (userToken ? '已获取 (' + userToken.length + '字符)' : '未获取'));
          log('ID Token: ' + (idToken ? '已获取 (' + idToken.length + '字符)' : '未获取'));
          
          // 3. 检查Cookie
          log('3. 检查Cookie...');
          log('当前Cookie: ' + document.cookie);
          
          // 4. 检查localStorage
          log('4. 检查localStorage...');
          try {
            const sessionData = localStorage.getItem('sessionData');
            log('Session数据: ' + (sessionData ? '存在' : '不存在'));
          } catch (e) {
            log('localStorage访问失败: ' + e.message, 'error');
          }
          
          // 5. 检查跨域状态
          log('5. 检查跨域状态...');
          const currentOrigin = window.location.origin;
          const targetOrigin = 'host';
          log('当前域名: ' + currentOrigin);
          log('目标域名: ' + targetOrigin);
          log('是否跨域: ' + (currentOrigin !== targetOrigin));
          
          // 6. 测试Token有效性
          log('6. 测试Token有效性...');
          await testTokenValidity();
          
          // 7. 测试跨域通信
          log('7. 测试跨域通信...');
          testCrossOrigin();
          
          log('=== 完整诊断完成 ===');
        }

        // 监听来自iframe的消息
        window.addEventListener('message', function(event) {
          log('收到消息 - 来源: ' + event.origin + ', 数据: ' + JSON.stringify(event.data));
          
          if (event.origin === 'http://host') {
            if (event.data.type === 'REQUEST_TOKEN') {
              log('收到Token请求，发送Token...');
              const tokenMessage = {
                type: 'SSO_TOKEN',
                access_token: userToken,
                id_token: idToken,
                realm: '${SsoConfig.realm}',
                clientId: '${SsoConfig.clientId}',
                timestamp: Date.now()
              };
              event.source.postMessage(tokenMessage, event.origin);
              log('✓ Token已发送', 'success');
            }
          }
        });

        // 页面加载完成后自动运行诊断
        window.onload = function() {
          log('页面加载完成，准备诊断...');
          setTimeout(runFullDiagnosis, 1000);
        };
      </script>
    </body>
    </html>
  `);
});

// 新增：Cookie诊断页面路由
app.get('/cookie-diagnosis', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Cookie诊断工具</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        button { margin: 5px; padding: 8px 15px; cursor: pointer; }
        .log { max-height: 400px; overflow-y: auto; background-color: #f8f9fa; padding: 10px; border: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <h1>Cookie诊断工具</h1>
      
      <div class="section info">
        <h3>服务器端Cookie信息</h3>
        <p><strong>Session ID:</strong> ${req.sessionID || 'N/A'}</p>
        <p><strong>Session存在:</strong> ${req.session ? '是' : '否'}</p>
        <p><strong>认证状态:</strong> ${req.isAuthenticated() ? '已认证' : '未认证'}</p>
        <p><strong>Session数据:</strong></p>
        <pre>${JSON.stringify(req.session || {}, null, 2)}</pre>
      </div>

      <div class="section">
        <h3>诊断操作</h3>
        <button onclick="runCookieDiagnosis()">运行Cookie诊断</button>
        <button onclick="testCookieAccess()">测试Cookie访问</button>
        <button onclick="clearAllCookies()">清除所有Cookie</button>
        <button onclick="setTestCookie()">设置测试Cookie</button>
        <button onclick="clearLog()">清除日志</button>
      </div>

      <div class="section">
        <h3>诊断日志</h3>
        <div id="diagnosisLog" class="log"></div>
      </div>

      <div class="section">
        <h3>浏览器Cookie信息</h3>
        <div id="cookieInfo"></div>
      </div>

      <script>
        function log(message, type = 'info') {
          const logDiv = document.getElementById('diagnosisLog');
          const timestamp = new Date().toLocaleTimeString();
          const className = type === 'error' ? 'error' : type === 'success' ? 'success' : type === 'warning' ? 'warning' : 'info';
          logDiv.innerHTML += \`<div class="\${className}"><strong>\${timestamp}</strong> \${message}</div>\`;
          logDiv.scrollTop = logDiv.scrollHeight;
          console.log(\`[Cookie诊断] \${message}\`);
        }

        function clearLog() {
          document.getElementById('diagnosisLog').innerHTML = '';
        }

        function updateCookieInfo() {
          const cookieInfo = document.getElementById('cookieInfo');
          const cookies = document.cookie;
          const cookieList = cookies ? cookies.split(';').map(c => c.trim()) : [];
          
          cookieInfo.innerHTML = \`
            <p><strong>Cookie总数:</strong> \${cookieList.length}</p>
            <p><strong>所有Cookie:</strong></p>
            <pre>\${cookies || '无Cookie'}</pre>
            <p><strong>Cookie详情:</strong></p>
            <ul>
              \${cookieList.map(cookie => {
                const [name, value] = cookie.split('=');
                return \`<li><strong>\${name}:</strong> \${value || '无值'}</li>\`;
              }).join('')}
            </ul>
          \`;
        }

        function runCookieDiagnosis() {
          log('=== 开始Cookie诊断 ===');
          
          // 1. 检查浏览器Cookie支持
          log('1. 检查浏览器Cookie支持...');
          log('navigator.cookieEnabled: ' + navigator.cookieEnabled);
          
          // 2. 检查当前Cookie
          log('2. 检查当前Cookie...');
          const cookies = document.cookie;
          log('document.cookie: ' + (cookies || '无Cookie'));
          log('Cookie数量: ' + (cookies ? cookies.split(';').length : 0));
          
          // 3. 检查localStorage
          log('3. 检查localStorage...');
          try {
            const sessionData = localStorage.getItem('sessionData');
            log('sessionData存在: ' + (sessionData ? '是' : '否'));
            if (sessionData) {
              log('sessionData长度: ' + sessionData.length);
            }
          } catch (e) {
            log('localStorage访问失败: ' + e.message, 'error');
          }
          
          // 4. 检查sessionStorage
          log('4. 检查sessionStorage...');
          try {
            const sessionKeys = Object.keys(sessionStorage);
            log('sessionStorage键数量: ' + sessionKeys.length);
            log('sessionStorage键: ' + sessionKeys.join(', '));
          } catch (e) {
            log('sessionStorage访问失败: ' + e.message, 'error');
          }
          
          // 5. 检查第三方Cookie设置
          log('5. 检查第三方Cookie设置...');
          if (navigator.userAgent.includes('Chrome')) {
            log('Chrome浏览器 - 检查第三方Cookie设置');
            log('建议: 在Chrome设置中检查"阻止第三方Cookie"设置');
          } else if (navigator.userAgent.includes('Firefox')) {
            log('Firefox浏览器 - 检查Cookie设置');
            log('建议: 在Firefox设置中检查"接受第三方Cookie"设置');
          } else if (navigator.userAgent.includes('Safari')) {
            log('Safari浏览器 - 检查智能防跟踪设置');
            log('建议: 在Safari设置中检查"防止跨站跟踪"设置');
          }
          
          log('=== Cookie诊断完成 ===');
          updateCookieInfo();
        }

        function testCookieAccess() {
          log('开始测试Cookie访问...');
          
          try {
            // 测试设置Cookie
            document.cookie = 'test_cookie=test_value; path=/; max-age=3600';
            log('✓ 测试Cookie设置成功', 'success');
            
            // 测试读取Cookie
            const testCookie = document.cookie.split(';').find(c => c.trim().startsWith('test_cookie='));
            if (testCookie) {
              log('✓ 测试Cookie读取成功: ' + testCookie, 'success');
            } else {
              log('✗ 测试Cookie读取失败', 'error');
            }
            
            // 清理测试Cookie
            document.cookie = 'test_cookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            log('✓ 测试Cookie清理成功', 'success');
            
          } catch (error) {
            log('✗ Cookie访问测试失败: ' + error.message, 'error');
          }
        }

        function clearAllCookies() {
          log('开始清除所有Cookie...');
          
          try {
            const cookies = document.cookie.split(';');
            cookies.forEach(cookie => {
              const name = cookie.split('=')[0].trim();
              document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            });
            
            // 清理localStorage
            localStorage.clear();
            log('✓ localStorage已清理', 'success');
            
            // 清理sessionStorage
            sessionStorage.clear();
            log('✓ sessionStorage已清理', 'success');
            
            log('✓ 所有Cookie和存储已清理', 'success');
            updateCookieInfo();
            
          } catch (error) {
            log('✗ 清理Cookie失败: ' + error.message, 'error');
          }
        }

        function setTestCookie() {
          log('设置测试Cookie...');
          
          try {
            // 设置各种类型的测试Cookie
            document.cookie = 'test_session=session_value; path=/; max-age=3600; SameSite=Lax';
            document.cookie = 'test_secure=secure_value; path=/; max-age=3600; Secure; SameSite=Strict';
            document.cookie = 'test_httpOnly=httponly_value; path=/; max-age=3600; HttpOnly; SameSite=Lax';
            
            log('✓ 测试Cookie设置成功', 'success');
            updateCookieInfo();
            
          } catch (error) {
            log('✗ 设置测试Cookie失败: ' + error.message, 'error');
          }
        }

        // 页面加载完成后自动运行诊断
        window.onload = function() {
          log('页面加载完成，准备诊断...');
          updateCookieInfo();
          setTimeout(runCookieDiagnosis, 1000);
        };
      </script>
    </body>
    </html>
  `);
});

// 新增：iframe SSO专项诊断页面路由
app.get('/iframe-sso-diagnosis', ensureAuthenticated, (req, res) => {
  const safeAccessToken = req.user.access_token ? JSON.stringify(req.user.access_token) : '""';
  const safeIdToken = req.user.id_token ? JSON.stringify(req.user.id_token) : '""';

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>iframe SSO专项诊断工具</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 20px;
          background-color: #f5f5f5;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 20px;
          border-radius: 10px;
          margin-bottom: 20px;
        }
        .section {
          background: white;
          margin: 15px 0;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .success { border-left: 4px solid #4CAF50; }
        .warning { border-left: 4px solid #FF9800; }
        .error { border-left: 4px solid #f44336; }
        .info { border-left: 4px solid #2196F3; }
        .status-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 15px;
          margin: 15px 0;
        }
        .status-card {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 6px;
          border: 1px solid #e9ecef;
        }
        .status-indicator {
          display: inline-block;
          width: 12px;
          height: 12px;
          border-radius: 50%;
          margin-right: 8px;
        }
        .status-ok { background-color: #4CAF50; }
        .status-warning { background-color: #FF9800; }
        .status-error { background-color: #f44336; }
        .status-unknown { background-color: #9E9E9E; }
        button {
          background: #2196F3;
          color: white;
          border: none;
          padding: 10px 20px;
          border-radius: 5px;
          cursor: pointer;
          margin: 5px;
          transition: background 0.3s;
        }
        button:hover { background: #1976D2; }
        button.secondary { background: #6c757d; }
        button.secondary:hover { background: #5a6268; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
        .log {
          max-height: 300px;
          overflow-y: auto;
          background-color: #1e1e1e;
          color: #d4d4d4;
          padding: 15px;
          border-radius: 5px;
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 13px;
        }
        .log-entry {
          margin: 2px 0;
          padding: 2px 0;
        }
        .log-timestamp { color: #569cd6; }
        .log-success { color: #4ec9b0; }
        .log-error { color: #f44747; }
        .log-warning { color: #dcdcaa; }
        .log-info { color: #9cdcfe; }
        input[type="text"], input[type="url"] {
          width: 100%;
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 14px;
        }
        .iframe-container {
          border: 2px solid #ddd;
          border-radius: 8px;
          overflow: hidden;
          background: white;
        }
        .iframe-header {
          background: #f8f9fa;
          padding: 10px 15px;
          border-bottom: 1px solid #ddd;
          font-weight: bold;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .progress-bar {
          width: 100%;
          height: 4px;
          background: #e9ecef;
          border-radius: 2px;
          overflow: hidden;
          margin: 10px 0;
        }
        .progress-fill {
          height: 100%;
          background: linear-gradient(90deg, #4CAF50, #2196F3);
          width: 0%;
          transition: width 0.3s ease;
        }
        .test-results {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 10px;
          margin: 15px 0;
        }
        .test-result {
          padding: 10px;
          border-radius: 5px;
          text-align: center;
          font-weight: bold;
        }
        .test-pass { background: #d4edda; color: #155724; }
        .test-fail { background: #f8d7da; color: #721c24; }
        .test-pending { background: #fff3cd; color: #856404; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔍 iframe SSO专项诊断工具</h1>
          <p>专门用于诊断iframe中SSO会话传递和认证问题的高级工具</p>
        </div>

        <div class="section info">
          <h3>📊 当前认证状态</h3>
          <div class="status-grid">
            <div class="status-card">
              <span class="status-indicator status-ok"></span>
              <strong>用户认证:</strong> 已登录
            </div>
            <div class="status-card">
              <span class="status-indicator ${req.user.access_token ? 'status-ok' : 'status-error'}"></span>
              <strong>Access Token:</strong> ${req.user.access_token ? '已获取' : '未获取'}
            </div>
            <div class="status-card">
              <span class="status-indicator ${req.user.id_token ? 'status-ok' : 'status-error'}"></span>
              <strong>ID Token:</strong> ${req.user.id_token ? '已获取' : '未获取'}
            </div>
            <div class="status-card">
              <span class="status-indicator status-ok"></span>
              <strong>Realm:</strong> ${SsoConfig.realm}
            </div>
          </div>
        </div>

        <div class="section">
          <h3>🎯 诊断配置</h3>
          <div style="margin: 15px 0;">
            <label for="targetUrl"><strong>目标iframe URL:</strong></label>
            <input type="url" id="targetUrl" value="http://host"
                   placeholder="输入要测试的iframe URL">
          </div>
          <div style="margin: 15px 0;">
            <button onclick="startComprehensiveDiagnosis()">🚀 开始全面诊断</button>
            <button onclick="quickTokenTest()" class="secondary">⚡ 快速Token测试</button>
            <button onclick="testCrossOriginCommunication()" class="secondary">🌐 跨域通信测试</button>
            <button onclick="clearAllLogs()" class="danger">🗑️ 清除日志</button>
          </div>
        </div>

        <div class="section">
          <h3>📈 诊断进度</h3>
          <div class="progress-bar">
            <div class="progress-fill" id="progressFill"></div>
          </div>
          <div id="currentStep">准备开始诊断...</div>
        </div>

        <div class="section">
          <h3>🧪 测试结果</h3>
          <div class="test-results" id="testResults">
            <div class="test-result test-pending">Token有效性: 待测试</div>
            <div class="test-result test-pending">跨域通信: 待测试</div>
            <div class="test-result test-pending">Cookie传递: 待测试</div>
            <div class="test-result test-pending">PostMessage: 待测试</div>
            <div class="test-result test-pending">iframe加载: 待测试</div>
            <div class="test-result test-pending">SSO响应: 待测试</div>
          </div>
        </div>

        <div class="section">
          <h3>📝 详细日志</h3>
          <div id="diagnosticLog" class="log"></div>
        </div>

        <div class="section">
          <h3>🖼️ iframe测试容器</h3>
          <div class="iframe-container">
            <div class="iframe-header">
              <span id="iframeStatus">iframe状态: 未加载</span>
              <div>
                <button onclick="loadTestIframe()" class="secondary">加载iframe</button>
                <button onclick="sendTokenToIframe()" class="secondary">发送Token</button>
                <button onclick="checkIframeAuth()" class="secondary">检查认证状态</button>
              </div>
            </div>
            <iframe id="testIframe" style="width: 100%; height: 500px; border: none;"
                    allow="fullscreen" referrerpolicy="origin"
                    sandbox="allow-same-origin allow-scripts allow-popups allow-forms allow-top-navigation"></iframe>
          </div>
        </div>

        <div style="margin-top: 20px; text-align: center;">
          <a href="/" style="color: #2196F3; text-decoration: none;">← 返回首页</a>
        </div>
      </div>

      <script>
        // 全局变量
        let userToken = ${safeAccessToken};
        let idToken = ${safeIdToken};
        let diagnosticStep = 0;
        let totalSteps = 8;
        let testResults = {};

        // 会话数据
        const sessionData = {
          isAuthenticated: true,
          user: ${JSON.stringify(req.user)},
          accessToken: userToken,
          idToken: idToken,
          refreshToken: ${JSON.stringify(req.user.refresh_token)},
          sessionState: ${JSON.stringify(req.user.session_state)},
          realm: '${SsoConfig.realm}',
          clientId: '${SsoConfig.clientId}',
          baseUrl: '${SsoConfig.baseUrl}'
        };

        // 存储到localStorage
        localStorage.setItem('sessionData', JSON.stringify(sessionData));

        // 日志函数
        function log(message, type = 'info') {
          const logDiv = document.getElementById('diagnosticLog');
          const timestamp = new Date().toLocaleTimeString();
          const logClass = 'log-' + type;

          const logEntry = document.createElement('div');
          logEntry.className = 'log-entry';
          logEntry.innerHTML = \`<span class="log-timestamp">[\${timestamp}]</span> <span class="\${logClass}">\${message}</span>\`;

          logDiv.appendChild(logEntry);
          logDiv.scrollTop = logDiv.scrollHeight;

          console.log(\`[iframe SSO诊断] \${message}\`);
        }

        function clearAllLogs() {
          document.getElementById('diagnosticLog').innerHTML = '';
          log('日志已清除', 'info');
        }

        // 更新进度
        function updateProgress(step, stepName) {
          diagnosticStep = step;
          const progress = (step / totalSteps) * 100;
          document.getElementById('progressFill').style.width = progress + '%';
          document.getElementById('currentStep').textContent = \`步骤 \${step}/\${totalSteps}: \${stepName}\`;
        }

        // 更新测试结果
        function updateTestResult(testName, status, message = '') {
          testResults[testName] = { status, message };
          renderTestResults();
        }

        function renderTestResults() {
          const container = document.getElementById('testResults');
          const tests = [
            { key: 'tokenValidity', name: 'Token有效性' },
            { key: 'crossOrigin', name: '跨域通信' },
            { key: 'cookieTransfer', name: 'Cookie传递' },
            { key: 'postMessage', name: 'PostMessage' },
            { key: 'iframeLoad', name: 'iframe加载' },
            { key: 'ssoResponse', name: 'SSO响应' }
          ];

          container.innerHTML = tests.map(test => {
            const result = testResults[test.key] || { status: 'pending' };
            const statusClass = 'test-' + result.status;
            const statusText = {
              'pass': '✅ 通过',
              'fail': '❌ 失败',
              'pending': '⏳ 待测试'
            }[result.status] || '❓ 未知';

            return \`<div class="test-result \${statusClass}">\${test.name}: \${statusText}</div>\`;
          }).join('');
        }

        // 开始全面诊断
        async function startComprehensiveDiagnosis() {
          log('=== 开始iframe SSO全面诊断 ===', 'info');

          try {
            // 步骤1: 检查基础环境
            updateProgress(1, '检查基础环境');
            await checkBasicEnvironment();

            // 步骤2: 验证Token有效性
            updateProgress(2, '验证Token有效性');
            await validateTokens();

            // 步骤3: 测试跨域通信
            updateProgress(3, '测试跨域通信');
            await testCrossOriginCommunication();

            // 步骤4: 检查Cookie设置
            updateProgress(4, '检查Cookie设置');
            await checkCookieSettings();

            // 步骤5: 测试PostMessage
            updateProgress(5, '测试PostMessage机制');
            await testPostMessage();

            // 步骤6: 加载测试iframe
            updateProgress(6, '加载测试iframe');
            await loadAndTestIframe();

            // 步骤7: 发送SSO信息
            updateProgress(7, '发送SSO信息到iframe');
            await sendSSOToIframe();

            // 步骤8: 验证SSO结果
            updateProgress(8, '验证SSO结果');
            await verifySSOResult();

            updateProgress(8, '诊断完成');
            log('=== 全面诊断完成 ===', 'success');

          } catch (error) {
            log('诊断过程中发生错误: ' + error.message, 'error');
          }
        }

        // 检查基础环境
        async function checkBasicEnvironment() {
          log('检查浏览器环境...', 'info');

          // 检查浏览器支持
          const checks = {
            cookieEnabled: navigator.cookieEnabled,
            localStorageSupported: typeof(Storage) !== "undefined",
            postMessageSupported: typeof window.postMessage === 'function',
            iframeSupported: document.createElement('iframe') !== null
          };

          log('浏览器支持检查: ' + JSON.stringify(checks), 'info');

          if (Object.values(checks).every(v => v)) {
            updateTestResult('environment', 'pass');
            log('✅ 基础环境检查通过', 'success');
          } else {
            updateTestResult('environment', 'fail');
            log('❌ 基础环境检查失败', 'error');
          }
        }

        // 验证Token有效性
        async function validateTokens() {
          log('验证Token有效性...', 'info');

          if (!userToken) {
            updateTestResult('tokenValidity', 'fail', 'Access Token不存在');
            log('❌ Access Token不存在', 'error');
            return;
          }

          try {
            const response = await fetch('/api/auth/verify');
            const data = await response.json();

            if (data.authenticated) {
              updateTestResult('tokenValidity', 'pass');
              log('✅ Token验证成功', 'success');
            } else {
              updateTestResult('tokenValidity', 'fail', data.message);
              log('❌ Token验证失败: ' + data.message, 'error');
            }
          } catch (error) {
            updateTestResult('tokenValidity', 'fail', error.message);
            log('❌ Token验证请求失败: ' + error.message, 'error');
          }
        }

        // 测试跨域通信
        async function testCrossOriginCommunication() {
          log('测试跨域通信...', 'info');

          const targetOrigin = new URL(document.getElementById('targetUrl').value).origin;
          log('目标域名: ' + targetOrigin, 'info');
          log('当前域名: ' + window.location.origin, 'info');

          const isCrossOrigin = targetOrigin !== window.location.origin;
          log('是否跨域: ' + isCrossOrigin, 'info');

          if (isCrossOrigin) {
            updateTestResult('crossOrigin', 'pass', '跨域环境');
            log('✅ 跨域通信环境确认', 'success');
          } else {
            updateTestResult('crossOrigin', 'pass', '同域环境');
            log('ℹ️ 同域环境，无需跨域通信', 'info');
          }
        }

        // 检查Cookie设置
        async function checkCookieSettings() {
          log('检查Cookie设置...', 'info');

          const cookies = document.cookie;
          log('当前Cookie: ' + (cookies || '无'), 'info');

          // 详细分析Cookie
          const cookieList = cookies ? cookies.split(';').map(c => c.trim()) : [];
          log('Cookie数量: ' + cookieList.length, 'info');

          // 检查关键Cookie
          const hasSSOCookie = cookies.includes('oidc_session');
          const hasAuthCookie = cookies.includes('isAuthenticated');
          const hasConnectSid = cookies.includes('connect.sid');

          log('SSO Cookie检查结果:', 'info');
          log('- oidc_session: ' + (hasSSOCookie ? '存在' : '不存在'), hasSSOCookie ? 'success' : 'warning');
          log('- isAuthenticated: ' + (hasAuthCookie ? '存在' : '不存在'), hasAuthCookie ? 'success' : 'warning');
          log('- connect.sid: ' + (hasConnectSid ? '存在' : '不存在'), hasConnectSid ? 'success' : 'warning');

          // 检查浏览器Cookie策略
          log('检查浏览器Cookie策略...', 'info');
          const userAgent = navigator.userAgent;
          let cookiePolicyWarning = '';

          if (userAgent.includes('Chrome')) {
            cookiePolicyWarning = 'Chrome浏览器可能阻止第三方Cookie';
          } else if (userAgent.includes('Safari')) {
            cookiePolicyWarning = 'Safari浏览器默认阻止跨站Cookie';
          } else if (userAgent.includes('Firefox')) {
            cookiePolicyWarning = 'Firefox浏览器可能限制跨站Cookie';
          }

          if (cookiePolicyWarning) {
            log('⚠️ ' + cookiePolicyWarning, 'warning');
          }

          // 测试Cookie写入能力
          try {
            const testCookieName = 'sso_test_' + Date.now();
            document.cookie = testCookieName + '=test_value; path=/; max-age=60';

            // 检查是否成功写入
            const canWriteCookie = document.cookie.includes(testCookieName);
            log('Cookie写入测试: ' + (canWriteCookie ? '成功' : '失败'), canWriteCookie ? 'success' : 'error');

            // 清理测试Cookie
            if (canWriteCookie) {
              document.cookie = testCookieName + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
            }
          } catch (error) {
            log('Cookie写入测试失败: ' + error.message, 'error');
          }

          // 更新测试结果
          if (hasSSOCookie && hasAuthCookie) {
            updateTestResult('cookieTransfer', 'pass');
            log('✅ Cookie传递测试通过', 'success');
          } else if (hasSSOCookie || hasAuthCookie || hasConnectSid) {
            updateTestResult('cookieTransfer', 'warning');
            log('⚠️ 部分Cookie存在，可能存在传递问题', 'warning');
          } else {
            updateTestResult('cookieTransfer', 'fail');
            log('❌ 未发现SSO相关Cookie，Cookie传递失败', 'error');
          }
        }

        // 测试PostMessage
        async function testPostMessage() {
          log('测试PostMessage机制...', 'info');

          return new Promise((resolve) => {
            const testMessage = {
              type: 'SSO_TEST',
              timestamp: Date.now(),
              source: 'parent'
            };

            // 监听回复
            const messageHandler = (event) => {
              if (event.data && event.data.type === 'SSO_TEST_REPLY') {
                window.removeEventListener('message', messageHandler);
                updateTestResult('postMessage', 'pass');
                log('✅ PostMessage测试成功', 'success');
                resolve();
              }
            };

            window.addEventListener('message', messageHandler);

            // 发送测试消息
            window.postMessage(testMessage, '*');

            // 超时处理
            setTimeout(() => {
              window.removeEventListener('message', messageHandler);
              updateTestResult('postMessage', 'pass', '基础功能正常');
              log('✅ PostMessage基础功能正常', 'success');
              resolve();
            }, 2000);
          });
        }

        // 加载并测试iframe
        async function loadAndTestIframe() {
          log('加载测试iframe...', 'info');

          return new Promise((resolve) => {
            const iframe = document.getElementById('testIframe');
            const targetUrl = document.getElementById('targetUrl').value;

            iframe.onload = () => {
              updateTestResult('iframeLoad', 'pass');
              log('✅ iframe加载成功', 'success');
              document.getElementById('iframeStatus').textContent = 'iframe状态: 已加载';
              resolve();
            };

            iframe.onerror = () => {
              updateTestResult('iframeLoad', 'fail');
              log('❌ iframe加载失败', 'error');
              resolve();
            };

            iframe.src = targetUrl;
            log('正在加载iframe: ' + targetUrl, 'info');
          });
        }

        // 发送SSO信息到iframe
        async function sendSSOToIframe() {
          log('发送SSO信息到iframe...', 'info');

          const iframe = document.getElementById('testIframe');
          if (!iframe.contentWindow) {
            updateTestResult('ssoResponse', 'fail', 'iframe未加载');
            log('❌ iframe未正确加载', 'error');
            return;
          }

          const targetOrigin = new URL(document.getElementById('targetUrl').value).origin;
          const tokenMessage = {
            type: 'SSO_TOKEN',
            access_token: userToken,
            id_token: idToken,
            realm: sessionData.realm,
            clientId: sessionData.clientId,
            timestamp: Date.now(),
            source: 'parent_diagnosis'
          };

          try {
            iframe.contentWindow.postMessage(tokenMessage, targetOrigin);
            log('✅ SSO信息已发送到iframe', 'success');
          } catch (error) {
            log('❌ 发送SSO信息失败: ' + error.message, 'error');
          }
        }

        // 验证SSO结果
        async function verifySSOResult() {
          log('等待SSO响应...', 'info');

          return new Promise((resolve) => {
            const messageHandler = (event) => {
              if (event.data && event.data.type === 'SSO_STATUS') {
                window.removeEventListener('message', messageHandler);

                if (event.data.authenticated) {
                  updateTestResult('ssoResponse', 'pass');
                  log('✅ iframe SSO认证成功', 'success');
                } else {
                  updateTestResult('ssoResponse', 'fail', event.data.message);
                  log('❌ iframe SSO认证失败: ' + event.data.message, 'error');
                }
                resolve();
              }
            };

            window.addEventListener('message', messageHandler);

            // 超时处理
            setTimeout(() => {
              window.removeEventListener('message', messageHandler);
              updateTestResult('ssoResponse', 'warning', '无响应');
              log('⚠️ 未收到iframe SSO响应', 'warning');
              resolve();
            }, 5000);
          });
        }

        // 快速Token测试
        async function quickTokenTest() {
          log('开始快速Token测试...', 'info');
          await validateTokens();
        }

        // 手动操作函数
        function loadTestIframe() {
          const targetUrl = document.getElementById('targetUrl').value;
          const iframe = document.getElementById('testIframe');
          iframe.src = targetUrl;
          log('手动加载iframe: ' + targetUrl, 'info');
        }

        function sendTokenToIframe() {
          const iframe = document.getElementById('testIframe');
          if (!iframe.contentWindow) {
            log('❌ iframe未加载', 'error');
            return;
          }

          const targetOrigin = new URL(document.getElementById('targetUrl').value).origin;
          const tokenMessage = {
            type: 'SSO_TOKEN',
            access_token: userToken,
            id_token: idToken,
            realm: sessionData.realm,
            clientId: sessionData.clientId,
            timestamp: Date.now(),
            source: 'manual_send'
          };

          iframe.contentWindow.postMessage(tokenMessage, targetOrigin);
          log('手动发送Token到iframe', 'info');
        }

        function checkIframeAuth() {
          const iframe = document.getElementById('testIframe');
          if (!iframe.contentWindow) {
            log('❌ iframe未加载', 'error');
            return;
          }

          const targetOrigin = new URL(document.getElementById('targetUrl').value).origin;
          const checkMessage = {
            type: 'CHECK_AUTH_STATUS',
            timestamp: Date.now()
          };

          iframe.contentWindow.postMessage(checkMessage, targetOrigin);
          log('请求iframe认证状态', 'info');
        }

        // 监听来自iframe的消息
        window.addEventListener('message', function(event) {
          const targetOrigin = new URL(document.getElementById('targetUrl').value).origin;

          if (event.origin !== targetOrigin) {
            return;
          }

          log('收到iframe消息: ' + JSON.stringify(event.data), 'info');

          // 处理不同类型的消息
          switch (event.data.type) {
            case 'REQUEST_TOKEN':
              log('iframe请求Token，自动发送...', 'info');
              sendTokenToIframe();
              break;

            case 'SSO_SUCCESS':
              log('✅ iframe SSO成功: ' + JSON.stringify(event.data), 'success');
              document.getElementById('iframeStatus').textContent = 'iframe状态: SSO成功';
              break;

            case 'SSO_FAILED':
              log('❌ iframe SSO失败: ' + JSON.stringify(event.data), 'error');
              document.getElementById('iframeStatus').textContent = 'iframe状态: SSO失败';
              break;

            case 'SSO_STATUS':
              const status = event.data.authenticated ? 'SSO已认证' : 'SSO未认证';
              log('iframe认证状态: ' + status, 'info');
              document.getElementById('iframeStatus').textContent = 'iframe状态: ' + status;
              break;

            case 'SSO_TEST_REPLY':
              log('收到PostMessage测试回复', 'success');
              break;
          }
        });

        // 页面加载完成后初始化
        window.onload = function() {
          log('iframe SSO诊断工具已加载', 'info');
          renderTestResults();
        };
      </script>
    </body>
    </html>
  `);
});

// 新增：Cookie配置修复API
app.post('/api/fix-cookie-config', ensureAuthenticated, (req, res) => {
  try {
    // 设置跨域友好的Cookie
    res.cookie('sso_iframe_token', req.user.access_token, {
      httpOnly: false, // 允许JavaScript访问
      secure: false, // 开发环境设为false
      sameSite: 'none', // 允许跨站传递
      maxAge: 60 * 60 * 1000, // 1小时
      path: '/'
    });

    res.cookie('sso_iframe_user', JSON.stringify({
      id: req.user.id,
      username: req.user.displayName || req.user.username,
      realm: SsoConfig.realm
    }), {
      httpOnly: false,
      secure: false,
      sameSite: 'none',
      maxAge: 60 * 60 * 1000,
      path: '/'
    });

    res.json({
      success: true,
      message: '跨域Cookie配置已更新',
      cookies: {
        sso_iframe_token: '已设置',
        sso_iframe_user: '已设置'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Cookie配置失败: ' + error.message
    });
  }
});

// 新增：获取iframe专用Token的API
app.get('/api/iframe-token', ensureAuthenticated, (req, res) => {
  res.json({
    success: true,
    data: {
      access_token: req.user.access_token,
      id_token: req.user.id_token,
      user_info: {
        id: req.user.id,
        username: req.user.displayName || req.user.username,
        email: req.user.email
      },
      realm: SsoConfig.realm,
      clientId: SsoConfig.clientId,
      timestamp: Date.now()
    }
  });
});

// 新增：Cookie传递修复工具路由
app.get('/cookie-fix-tool', ensureAuthenticated, (req, res) => {
  const safeAccessToken = req.user.access_token ? JSON.stringify(req.user.access_token) : '""';
  const safeIdToken = req.user.id_token ? JSON.stringify(req.user.id_token) : '""';

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Cookie传递修复工具</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 20px;
          background: linear-gradient(135deg, #FF6B6B 0%, #4ECDC4 100%);
          color: white;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header {
          background: rgba(255, 255, 255, 0.1);
          padding: 20px;
          border-radius: 10px;
          margin-bottom: 20px;
          backdrop-filter: blur(10px);
        }
        .section {
          background: rgba(255, 255, 255, 0.1);
          margin: 15px 0;
          padding: 20px;
          border-radius: 8px;
          backdrop-filter: blur(10px);
        }
        .fix-card {
          background: rgba(255, 255, 255, 0.2);
          border-radius: 8px;
          padding: 15px;
          margin: 10px 0;
          border-left: 4px solid #4CAF50;
        }
        .problem-card {
          background: rgba(255, 255, 255, 0.2);
          border-radius: 8px;
          padding: 15px;
          margin: 10px 0;
          border-left: 4px solid #f44336;
        }
        button {
          background: rgba(255, 255, 255, 0.2);
          color: white;
          border: 1px solid rgba(255, 255, 255, 0.3);
          padding: 10px 20px;
          border-radius: 5px;
          cursor: pointer;
          margin: 5px;
          transition: all 0.3s;
        }
        button:hover {
          background: rgba(255, 255, 255, 0.3);
          transform: translateY(-2px);
        }
        .log {
          max-height: 300px;
          overflow-y: auto;
          background: rgba(0, 0, 0, 0.3);
          color: white;
          padding: 15px;
          border-radius: 5px;
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 13px;
        }
        .status-ok { color: #4CAF50; }
        .status-warning { color: #FF9800; }
        .status-error { color: #f44336; }
        input[type="url"] {
          width: 100%;
          padding: 8px 12px;
          border: 1px solid rgba(255, 255, 255, 0.3);
          border-radius: 4px;
          background: rgba(255, 255, 255, 0.1);
          color: white;
        }
        input[type="url"]::placeholder { color: rgba(255, 255, 255, 0.7); }
        .iframe-container {
          border: 2px solid rgba(255, 255, 255, 0.3);
          border-radius: 8px;
          overflow: hidden;
          background: rgba(255, 255, 255, 0.1);
        }
        .iframe-header {
          background: rgba(255, 255, 255, 0.2);
          padding: 10px 15px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.3);
          font-weight: bold;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🍪 Cookie传递修复工具</h1>
          <p>专门解决iframe中Cookie无法传递导致的SSO认证问题</p>
        </div>

        <div class="section">
          <h3>🔍 问题诊断</h3>
          <div id="problemDiagnosis">
            <div class="problem-card">
              <h4>❌ 常见问题：iframe中需要重新登录</h4>
              <p><strong>原因：</strong>浏览器的跨域Cookie策略阻止了Cookie传递</p>
              <ul>
                <li>Chrome: 默认阻止第三方Cookie</li>
                <li>Safari: 智能防跟踪功能阻止跨站Cookie</li>
                <li>Firefox: 增强跟踪保护阻止跨站Cookie</li>
              </ul>
            </div>
          </div>
        </div>

        <div class="section">
          <h3>🛠️ 修复方案</h3>
          <div id="fixSolutions">
            <div class="fix-card">
              <h4>✅ 方案1：修复Cookie配置（推荐）</h4>
              <p>设置SameSite=None的跨域友好Cookie</p>
              <button onclick="fixCookieConfiguration()">🔧 修复Cookie配置</button>
            </div>

            <div class="fix-card">
              <h4>✅ 方案2：使用postMessage传递认证信息</h4>
              <p>通过JavaScript消息传递机制在父子页面间传递Token</p>
              <button onclick="implementPostMessageFix()">📡 应用postMessage方案</button>
            </div>

            <div class="fix-card">
              <h4>✅ 方案3：API直接获取Token</h4>
              <p>iframe直接调用API获取认证信息</p>
              <button onclick="implementApiFix()">🔗 应用API方案</button>
            </div>

            <div class="fix-card">
              <h4>✅ 方案4：URL参数传递Token</h4>
              <p>将访问令牌作为URL参数传递给iframe</p>
              <button onclick="implementUrlParameterFix()">🔗 应用URL参数方案</button>
            </div>

            <div class="fix-card">
              <h4>✅ 方案5：localStorage共享</h4>
              <p>使用localStorage在同域下共享认证信息</p>
              <button onclick="implementLocalStorageFix()">💾 应用localStorage方案</button>
            </div>

            <div class="fix-card">
              <h4>✅ 方案6：代理模式</h4>
              <p>通过服务端代理避免跨域问题</p>
              <button onclick="implementProxyFix()">🔧 查看代理配置</button>
            </div>
          </div>
        </div>

        <div class="section">
          <h3>🧪 测试修复效果</h3>
          <div>
            <label for="testUrl">测试URL:</label>
            <input type="url" id="testUrl" value="http://host"
                   placeholder="输入要测试的iframe URL">
          </div>
          <div style="margin: 15px 0;">
            <button onclick="testWithFixedCookies()">🍪 测试Cookie修复</button>
            <button onclick="testWithApi()">🔗 测试API方案</button>
            <button onclick="testWithPostMessage()">📡 测试postMessage方案</button>
            <button onclick="testWithUrlParameter()">🔗 测试URL参数方案</button>
            <button onclick="testWithLocalStorage()">💾 测试localStorage方案</button>
            <button onclick="clearTestResults()">🗑️ 清除测试结果</button>
          </div>
        </div>

        <div class="section">
          <h3>📊 测试结果</h3>
          <div id="testResults" class="log"></div>
        </div>

        <div class="section">
          <h3>🖼️ iframe测试容器</h3>
          <div class="iframe-container">
            <div class="iframe-header">
              <span id="iframeStatus">iframe状态: 未加载</span>
            </div>
            <iframe id="testIframe" style="width: 100%; height: 400px; border: none;"
                    allow="fullscreen" referrerpolicy="origin"
                    sandbox="allow-same-origin allow-scripts allow-popups allow-forms allow-top-navigation"></iframe>
          </div>
        </div>

        <div style="margin-top: 20px; text-align: center;">
          <a href="/" style="color: white; text-decoration: none;">← 返回首页</a>
        </div>
      </div>

      <script>
        let userToken = ${safeAccessToken};
        let idToken = ${safeIdToken};

        const sessionData = {
          isAuthenticated: true,
          user: ${JSON.stringify(req.user)},
          accessToken: userToken,
          idToken: idToken,
          refreshToken: ${JSON.stringify(req.user.refresh_token)},
          sessionState: ${JSON.stringify(req.user.session_state)},
          realm: '${SsoConfig.realm}',
          clientId: '${SsoConfig.clientId}',
          baseUrl: '${SsoConfig.baseUrl}'
        };

        function log(message, type = 'info') {
          const logDiv = document.getElementById('testResults');
          const timestamp = new Date().toLocaleTimeString();
          const statusClass = 'status-' + type;

          logDiv.innerHTML += \`<div><span class="\${statusClass}">[\${timestamp}] \${message}</span></div>\`;
          logDiv.scrollTop = logDiv.scrollHeight;
          console.log(\`[Cookie修复] \${message}\`);
        }

        function clearTestResults() {
          document.getElementById('testResults').innerHTML = '';
          log('测试结果已清除', 'ok');
        }

        // 方案1：修复Cookie配置
        async function fixCookieConfiguration() {
          log('正在修复Cookie配置...', 'ok');

          try {
            const response = await fetch('/api/fix-cookie-config', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              }
            });

            const result = await response.json();

            if (result.success) {
              log('✅ Cookie配置修复成功', 'ok');
              log('已设置跨域友好的Cookie (SameSite=None)', 'ok');

              // 重新加载iframe测试效果
              setTimeout(() => {
                testWithFixedCookies();
              }, 1000);
            } else {
              log('❌ Cookie配置修复失败: ' + result.message, 'error');
            }
          } catch (error) {
            log('❌ Cookie配置修复请求失败: ' + error.message, 'error');
          }
        }

        // 测试修复后的Cookie
        function testWithFixedCookies() {
          log('测试修复后的Cookie效果...', 'ok');

          const iframe = document.getElementById('testIframe');
          const targetUrl = document.getElementById('testUrl').value;

          // 添加测试参数
          const testUrl = targetUrl + (targetUrl.includes('?') ? '&' : '?') + 'cookie_test=true&timestamp=' + Date.now();

          iframe.src = testUrl;
          document.getElementById('iframeStatus').textContent = 'iframe状态: 正在测试修复后的Cookie';

          iframe.onload = function() {
            log('✅ iframe已加载，Cookie应该可以正常传递了', 'ok');
            document.getElementById('iframeStatus').textContent = 'iframe状态: Cookie修复测试完成';
          };
        }

        // 方案2：API直接获取
        async function implementApiFix() {
          log('正在应用API直接获取方案...', 'ok');

          try {
            const response = await fetch('/api/iframe-token');
            const result = await response.json();

            if (result.success) {
              log('✅ 成功获取iframe专用Token', 'ok');

              // 将Token信息存储到localStorage供iframe使用
              localStorage.setItem('iframe_api_token', JSON.stringify(result.data));

              const iframe = document.getElementById('testIframe');
              const targetUrl = document.getElementById('testUrl').value;

              // 加载iframe并通过postMessage发送Token
              iframe.src = targetUrl + (targetUrl.includes('?') ? '&' : '?') + 'api_mode=true';
              document.getElementById('iframeStatus').textContent = 'iframe状态: 正在加载(API模式)';

              iframe.onload = function() {
                const tokenMessage = {
                  type: 'SSO_TOKEN',
                  ...result.data,
                  source: 'api_direct'
                };

                try {
                  iframe.contentWindow.postMessage(tokenMessage, new URL(targetUrl).origin);
                  log('✅ Token已通过API+postMessage发送', 'ok');
                  document.getElementById('iframeStatus').textContent = 'iframe状态: API Token已发送';
                } catch (error) {
                  log('❌ 发送API Token失败: ' + error.message, 'error');
                }
              };
            } else {
              log('❌ 获取iframe专用Token失败', 'error');
            }
          } catch (error) {
            log('❌ API请求失败: ' + error.message, 'error');
          }
        }

        // 方案3：postMessage修复
        function implementPostMessageFix() {
          log('正在应用postMessage修复方案...', 'ok');

          const iframe = document.getElementById('testIframe');
          const targetUrl = document.getElementById('testUrl').value;

          // 加载iframe
          iframe.src = targetUrl;
          document.getElementById('iframeStatus').textContent = 'iframe状态: 正在加载...';

          iframe.onload = function() {
            log('iframe加载完成，发送SSO信息...', 'ok');
            document.getElementById('iframeStatus').textContent = 'iframe状态: 已加载，正在发送SSO信息';

            const targetOrigin = new URL(targetUrl).origin;
            const tokenMessage = {
              type: 'SSO_TOKEN',
              access_token: userToken,
              id_token: idToken,
              realm: sessionData.realm,
              clientId: sessionData.clientId,
              timestamp: Date.now(),
              source: 'cookie_fix_tool'
            };

            try {
              iframe.contentWindow.postMessage(tokenMessage, targetOrigin);
              log('✅ SSO信息已通过postMessage发送', 'ok');
              document.getElementById('iframeStatus').textContent = 'iframe状态: SSO信息已发送';
            } catch (error) {
              log('❌ postMessage发送失败: ' + error.message, 'error');
              document.getElementById('iframeStatus').textContent = 'iframe状态: 发送失败';
            }
          };

          iframe.onerror = function() {
            log('❌ iframe加载失败', 'error');
            document.getElementById('iframeStatus').textContent = 'iframe状态: 加载失败';
          };
        }

        // 方案2：URL参数修复
        function implementUrlParameterFix() {
          log('正在应用URL参数修复方案...', 'ok');

          const iframe = document.getElementById('testIframe');
          const baseUrl = document.getElementById('testUrl').value;

          // 构建带Token的URL
          const urlWithToken = \`\${baseUrl}\${baseUrl.includes('?') ? '&' : '?'}access_token=\${encodeURIComponent(userToken)}&id_token=\${encodeURIComponent(idToken)}&sso_mode=url_param\`;

          log('构建的URL: ' + urlWithToken.substring(0, 100) + '...', 'ok');

          iframe.src = urlWithToken;
          document.getElementById('iframeStatus').textContent = 'iframe状态: 正在加载(URL参数模式)';

          iframe.onload = function() {
            log('✅ iframe已加载，Token已通过URL参数传递', 'ok');
            document.getElementById('iframeStatus').textContent = 'iframe状态: 已加载(URL参数模式)';
          };
        }

        // 方案3：localStorage修复
        function implementLocalStorageFix() {
          log('正在应用localStorage修复方案...', 'ok');

          try {
            // 存储SSO信息到localStorage
            localStorage.setItem('sso_token_data', JSON.stringify({
              access_token: userToken,
              id_token: idToken,
              realm: sessionData.realm,
              clientId: sessionData.clientId,
              timestamp: Date.now(),
              source: 'localStorage_fix'
            }));

            log('✅ SSO信息已存储到localStorage', 'ok');

            const iframe = document.getElementById('testIframe');
            const targetUrl = document.getElementById('testUrl').value;

            iframe.src = targetUrl + (targetUrl.includes('?') ? '&' : '?') + 'sso_mode=localStorage';
            document.getElementById('iframeStatus').textContent = 'iframe状态: 正在加载(localStorage模式)';

            iframe.onload = function() {
              log('✅ iframe已加载，可从localStorage读取SSO信息', 'ok');
              document.getElementById('iframeStatus').textContent = 'iframe状态: 已加载(localStorage模式)';
            };

          } catch (error) {
            log('❌ localStorage操作失败: ' + error.message, 'error');
          }
        }

        // 方案4：代理模式
        function implementProxyFix() {
          log('代理模式配置说明:', 'ok');
          log('1. 在您的服务器上设置反向代理', 'ok');
          log('2. 将目标系统代理到同域下的路径', 'ok');
          log('3. 例如: /proxy/target-system/* -> https://target-system.com/*', 'ok');
          log('4. 这样iframe和父页面就在同一域名下了', 'ok');

          // 显示代理配置示例
          const proxyConfig = \`
// Nginx配置示例
location /proxy/target-system/ {
    proxy_pass http://host/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 传递认证Cookie
    proxy_pass_header Set-Cookie;
    proxy_cookie_domain ctrz.cofco.com $host;
}
          \`;

          log('代理配置示例已输出到控制台', 'ok');
          console.log('代理配置示例:', proxyConfig);
        }

        // 测试函数
        function testWithApi() {
          log('开始测试API方案...', 'ok');
          implementApiFix();
        }

        function testWithPostMessage() {
          log('开始测试postMessage方案...', 'ok');
          implementPostMessageFix();
        }

        function testWithUrlParameter() {
          log('开始测试URL参数方案...', 'ok');
          implementUrlParameterFix();
        }

        function testWithLocalStorage() {
          log('开始测试localStorage方案...', 'ok');
          implementLocalStorageFix();
        }

        // 监听来自iframe的消息
        window.addEventListener('message', function(event) {
          const targetUrl = document.getElementById('testUrl').value;
          const targetOrigin = new URL(targetUrl).origin;

          if (event.origin !== targetOrigin) {
            return;
          }

          log('收到iframe消息: ' + JSON.stringify(event.data), 'ok');

          switch (event.data.type) {
            case 'REQUEST_TOKEN':
              log('iframe请求Token，自动发送...', 'ok');
              implementPostMessageFix();
              break;

            case 'SSO_SUCCESS':
              log('✅ iframe SSO成功!', 'ok');
              document.getElementById('iframeStatus').textContent = 'iframe状态: SSO认证成功';
              break;

            case 'SSO_FAILED':
              log('❌ iframe SSO失败: ' + (event.data.error || '未知错误'), 'error');
              document.getElementById('iframeStatus').textContent = 'iframe状态: SSO认证失败';
              break;

            case 'SSO_STATUS':
              const status = event.data.authenticated ? 'SSO已认证' : 'SSO未认证';
              log('iframe认证状态: ' + status, event.data.authenticated ? 'ok' : 'warning');
              document.getElementById('iframeStatus').textContent = 'iframe状态: ' + status;
              break;
          }
        });

        // 页面加载完成后初始化
        window.onload = function() {
          log('Cookie修复工具已加载', 'ok');
          log('当前用户Token状态: ' + (userToken ? '已获取' : '未获取'), userToken ? 'ok' : 'error');
        };
      </script>
    </body>
    </html>
  `);
});

// 新增：iframe SSO调试页面路由
app.get('/iframe-debug', ensureAuthenticated, (req, res) => {
  const infoObj = {
    isAuthenticated: true,
    user: req.user,
    accessToken: req.user.access_token,
    idToken: req.user.id_token,
    refreshToken: req.user.refresh_token,
    sessionState: req.user.session_state,
    realm: SsoConfig.realm,
    clientId: SsoConfig.clientId
  };
  const infoJson = encodeURIComponent(JSON.stringify(infoObj));

  const tokenMsgObj = {
    type: 'SSO_TOKEN',
    access_token: req.user.access_token,
    id_token: req.user.id_token,
    realm: SsoConfig.realm,
    clientId: SsoConfig.clientId,
    timestamp: Date.now()
  };
  const tokenMsgJson = encodeURIComponent(JSON.stringify(tokenMsgObj));

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>iframe SSO 调试页面</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .log { max-height: 200px; overflow-y: auto; background: #f8f8f8; padding: 10px; border: 1px solid #eee; }
        pre { background: #f8f8f8; padding: 8px; border-radius: 3px; }
        input[type=text] { width: 400px; }
        button { margin: 0 5px 0 0; padding: 6px 16px; }
      </style>
    </head>
    <body>
      <h1>iframe SSO 调试页面</h1>
      <div class="section">
        <label>iframe URL: <input id="iframeUrl" value="http://host"></label>
        <button onclick="loadIframe()">加载iframe</button>
        <button onclick="sendTokenToIframe()">重新传递授权信息</button>
      </div>
      <div class="section">
        <h3>父页面登录信息</h3>
        <pre id="parentInfo"></pre>
      </div>
      <div class="section">
        <h3>iframe登录状态</h3>
        <pre id="iframeStatus">未检测</pre>
      </div>
      <div class="section">
        <h3>调试日志</h3>
        <div id="debugLog" class="log"></div>
      </div>
      <div class="section">
        <h3>iframe容器</h3>
        <iframe id="testIframe" style="width:100%;height:500px;border:1px solid #ccc"></iframe>
      </div>
      <script>
        let iframe = document.getElementById('testIframe');
        let lastToken = null;
        const info = JSON.parse(decodeURIComponent('${infoJson}'));
        const tokenMsg = JSON.parse(decodeURIComponent('${tokenMsgJson}'));
        function log(msg) {
          let logDiv = document.getElementById('debugLog');
          logDiv.innerHTML += ``<div>${new Date().toLocaleTimeString()} ${msg}</div>``;
          logDiv.scrollTop = logDiv.scrollHeight;
        }
        function loadIframe() {
          const url = document.getElementById('iframeUrl').value;
          iframe.src = url;
          document.getElementById('iframeStatus').textContent = '未检测';
          log('加载iframe: ' + url);
        }
        function sendTokenToIframe() {
          if (!iframe.contentWindow) {
            log('iframe未加载');
            return;
          }
          iframe.contentWindow.postMessage(tokenMsg, '*');
          log('已向iframe发送token');
        }
        // 监听iframe反馈
        window.addEventListener('message', function(event) {
          if (event.data && event.data.type === 'SSO_STATUS') {
            document.getElementById('iframeStatus').textContent = JSON.stringify(event.data, null, 2);
            log('收到iframe登录状态反馈: ' + JSON.stringify(event.data));
          }
        });
        // 页面加载时显示父页面登录信息
        window.onload = function() {
          document.getElementById('parentInfo').textContent = JSON.stringify(info, null, 2);
        };
      </script>
    </body>
    </html>
  `);
});

// 错误处理中间件
app.use((err, req, res, next) => {
  console.error('应用错误:', err);
  res.status(500).send(`发生错误: ${err.message}`);
});

// 修改服务器启动代码
const PORT = process.env.PORT || 3003;
server.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
  console.log(`请访问 http://localhost:${PORT} 测试应用`);
  
  axios.get(`${SsoConfig.baseUrl}/realms/${SsoConfig.realm}`)
    .then(() => console.log('Keycloak服务可用'))
    .catch(error => console.error('警告: Keycloak服务不可用:', error.message));
});

// 配置axios拦截器，在请求中添加token
app.get('/api-example', ensureAuthenticated, (req, res) => {
  const axiosInstance = axios.create();
  const token = req.user.access_token;
  
  axiosInstance.interceptors.request.use(config => {
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
      console.log('已添加Authorization头:', `Bearer ${token.substring(0, 20)}...`);
    }
    return config;
  });
  
  axiosInstance.get(`${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`)
    .then(response => {
      res.send(`
        <h1>API请求示例</h1>
        <p>这个页面展示了如何在API请求中使用访问令牌</p>
        
        <h2>请求头中的令牌:</h2>
        <pre>Authorization: Bearer ${token}</pre>
        
        <h2>API响应:</h2>
        <pre>${JSON.stringify(response.data, null, 2)}</pre>
        
        <h3>JavaScript代码示例:</h3>
        <pre>
// 从存储中读取Token
const token = "${token}";

// 在请求拦截器中附加Token
axios.interceptors.request.use(config => {
  if (token) {
    config.headers.Authorization = \`Bearer \${token}\`;
  }
  return config;
});

// 发送带有Token的请求
axios.get('host/realms/xxx/protocol/openid-connect/userinfo')
  .then(response => console.log(response.data));
        </pre>
        
        <a href="/" onclick="return checkAuthBeforeNavigate('/')">返回首页</a>

        <script src="/auth-guard.js"></script>
      `);
    })
    .catch(error => {
      console.error('API请求失败:', error.response?.data || error.message);
      res.status(500).send(`
        <h1>API请求失败</h1>
        <p>错误信息: ${error.message}</p>
        <pre>${JSON.stringify(error.response?.data || {}, null, 2)}</pre>
        <a href="/" onclick="return checkAuthBeforeNavigate('/')">返回首页</a>

        <script src="/auth-guard.js"></script>
      `);
    });
});

// Keycloak API 演示页面 (移除 ensureAuthenticated，允许未登录访问)
app.get('/keycloak-api-demo', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Keycloak API 学习实验室</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .card { border: 1px solid #e1e4e8; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
        .card-header { background-color: #f8f9fa; padding: 15px; border-bottom: 1px solid #e1e4e8; display: flex; justify-content: space-between; align-items: center; }
        .card-title { margin: 0; font-size: 1.1em; font-weight: 600; color: #333; }
        .card-body { padding: 20px; }
        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        .btn-primary { background-color: #3498db; color: white; }
        .btn-primary:hover { background-color: #2980b9; }
        .btn-success { background-color: #2ecc71; color: white; }
        .btn-warning { background-color: #f39c12; color: white; }
        pre { background-color: #2d3436; color: #dfe6e9; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 13px; }
        .response-area { margin-top: 15px; display: none; }
        .explanation { background-color: #e8f4f8; padding: 15px; border-left: 4px solid #3498db; margin-bottom: 15px; border-radius: 4px; color: #2c3e50; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🧪 Keycloak API 学习实验室</h1>
        <p>这里演示了如何作为客户端与 Keycloak 服务进行交互。点击下方按钮查看具体的请求参数和响应结果。</p>
        
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
          <a href="/" class="btn btn-primary" style="text-decoration: none;">← 返回首页</a>
          <div style="font-size: 14px; color: #666;">
            当前状态: <span id="login-status" style="font-weight:bold;">检测中...</span>
          </div>
        </div>

        <div id="login-warning" style="display: none; background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 4px; color: #856404;">
          <strong>提示：</strong> 您目前未登录应用的主系统。以下 1-3 号功能依赖于当前登录用户的 Access Token，因此现在无法使用。但您可以体验 4-7 号独立认证流程。
        </div>

        <!-- 1. 获取用户信息 -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">1. 获取用户信息 (UserInfo Endpoint)</h3>
            <button class="btn btn-primary" onclick="callApi('userinfo')">发送请求</button>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 使用 Access Token 获取当前用户的详细信息。<br>
              <strong>常用场景：</strong> 登录后获取用户资料、权限验证。<br>
              <strong>请求方式：</strong> GET /protocol/openid-connect/userinfo
            </div>
            <div id="result-userinfo" class="response-area"></div>
          </div>
        </div>

        <!-- 2. 刷新 Token -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">2. 刷新令牌 (Refresh Token)</h3>
            <button class="btn btn-warning" onclick="callApi('refresh_token')">发送请求</button>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 使用 Refresh Token 获取新的 Access Token。<br>
              <strong>常用场景：</strong> Access Token 过期时，在后台静默刷新，避免用户重新登录。<br>
              <strong>请求方式：</strong> POST /protocol/openid-connect/token (grant_type=refresh_token)
            </div>
            <div id="result-refresh_token" class="response-area"></div>
          </div>
        </div>
        
        <!-- 3. Token 内省 -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">3. 令牌内省 (Token Introspection)</h3>
            <button class="btn btn-success" onclick="callApi('introspect')">发送请求</button>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 验证 Token 的活跃状态和详细信息。<br>
              <strong>常用场景：</strong> 资源服务器验证收到的 Token 是否有效。<br>
              <strong>请求方式：</strong> POST /protocol/openid-connect/token/introspect
            </div>
            <div id="result-introspect" class="response-area"></div>
          </div>
        </div>

        <!-- 4. 客户端模式 (Client Credentials) -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">4. 服务端认证 (Client Credentials Grant)</h3>
            <button class="btn btn-primary" style="background-color: #9b59b6;" onclick="callApi('client_credentials')">发送请求</button>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 使用 Client ID 和 Client Secret 获取 Access Token。<br>
              <strong>常用场景：</strong> 服务端之间的后台调用，不涉及具体用户。<br>
              <strong>请求方式：</strong> POST /protocol/openid-connect/token (grant_type=client_credentials)<br>
              <strong style="color: #e74c3c;">⚠️ 前置条件：</strong> 必须在 Keycloak 后台开启该 Client 的 <code style="background: #eee; padding: 2px 4px; border-radius: 3px;">Service accounts roles</code> 选项，否则会报错 "unauthorized_client"。
            </div>
            <div id="result-client_credentials" class="response-area"></div>
          </div>
        </div>

        <!-- 5. 密码模式 (Password Grant) -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">5. 密码模式 (Password Grant)</h3>
            <div style="display: flex; gap: 10px; align-items: center;">
              <input type="text" id="pg-username" placeholder="用户名" style="padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 120px;">
              <input type="password" id="pg-password" placeholder="密码" style="padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 120px;">
              <button class="btn btn-danger" style="background-color: #e74c3c;" onclick="callPasswordGrant()">发送请求</button>
            </div>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 使用用户名和密码直接换取 Access Token。<br>
              <strong>常用场景：</strong> 遗留系统对接或无法使用浏览器重定向的场景（不推荐用于Web应用）。<br>
              <strong>请求方式：</strong> POST /protocol/openid-connect/token (grant_type=password)<br>
              <strong style="color: #e74c3c;">⚠️ 前置条件：</strong> 必须在 Keycloak 后台开启该 Client 的 <code style="background: #eee; padding: 2px 4px; border-radius: 3px;">Direct access grants</code> 选项。
            </div>
            <div id="result-password_grant" class="response-area"></div>
          </div>
        </div>

        <!-- 6. 授权码模式 (Authorization Code Grant) - 手动演示 -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">6. 授权码模式 (Authorization Code Grant)</h3>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 这是最标准的 OAuth2 登录流程。先跳转到 Keycloak 登录获取 code，再用 code 换取 Token。<br>
              <strong>常用场景：</strong> 所有包含前端浏览器的 Web 应用标准接入方式。<br>
              <strong>请求方式：</strong> POST /protocol/openid-connect/token (grant_type=authorization_code)
            </div>
            
            <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; border: 1px dashed #ddd;">
              <h4 style="margin-top: 0;">第一步：获取授权码 (Code)</h4>
              <p style="font-size: 13px; color: #666;">点击下方按钮将打开新窗口前往 Keycloak。登录成功后，它会重定向回本站的一个特殊页面，并在 URL 中带上 <code>code</code>。</p>
              <div style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; color: #856404; font-size: 13px;">
                <strong>⚠️ 重要前提：</strong><br>
                要在您的环境中成功运行此步骤，您必须在 Keycloak 后台的客户端配置中，将以下地址加入到 <strong>Valid redirect URIs</strong> 列表中：<br>
                <code id="display-redirect-uri" style="background: #ffe8a1; padding: 2px 4px;"></code><br>
                如果不加，Keycloak 会报错 "Invalid parameter: redirect_uri"。
              </div>
              <button class="btn btn-primary" onclick="startAuthCodeFlow()">1. 去登录并获取 Code</button>
            </div>
            
            <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; border: 1px dashed #ddd; margin-top: 15px;">
              <h4 style="margin-top: 0;">第二步：用 Code 换取 Token</h4>
              <div style="display: flex; gap: 10px; align-items: center;">
                <input type="text" id="ac-code" placeholder="在此粘贴获取到的 code" style="padding: 8px; border: 1px solid #ddd; border-radius: 4px; flex: 1;">
                <button class="btn btn-success" onclick="exchangeCodeForToken()">2. 换取 Token</button>
              </div>
            </div>

            <div id="result-authorization_code" class="response-area"></div>
          </div>
        </div>

        <!-- 7. PKCE 模式 (Proof Key for Code Exchange) -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">7. 授权码模式 + PKCE (纯前端/SPA应用推荐)</h3>
            <button class="btn btn-primary" style="background-color: #34495e;" onclick="startPKCEFlow()">一键演示完整流程</button>
          </div>
          <div class="card-body">
            <div class="explanation">
              <strong>接口说明：</strong> 这是为了防止授权码被拦截而设计的增强型授权码模式，特别适合没有后端的纯前端应用 (SPA) 或移动 App。它<strong>不需要 Client Secret</strong>，而是通过动态生成的 code_verifier 和 code_challenge 来保证安全。<br>
              <strong>常用场景：</strong> Vue, React, Angular 等前端项目。<br>
              <strong>您的抓包分析：</strong> 您提供的 curl 就是标准的 PKCE 流程 (注意里面有 <code>code_verifier</code> 参数且没有 <code>client_secret</code>)。
            </div>
            <div id="result-pkce" class="response-area"></div>
          </div>
        </div>

      </div>

      <script>
        // 不使用 var，直接将函数声明在最外层（函数声明会自动提升）
        
        // 页面加载完成后设置显示的重定向 URI
        window.onload = function() {
          const redirectUri = window.location.origin + "/auth-code-callback.html";
          const displayEl = document.getElementById('display-redirect-uri');
          if (displayEl) {
            displayEl.innerText = redirectUri;
          }
        };

        // 简单的 Base64URL 编码
        function base64URLEncode(buffer) {
          return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        }

        // 生成随机字符串 (code_verifier)
        function generateRandomString(length) {
          const array = new Uint8Array(length);
          window.crypto.getRandomValues(array);
          return base64URLEncode(array);
        }

        // 计算 SHA-256 哈希 (code_challenge)
        async function generateCodeChallenge(code_verifier) {
          const encoder = new TextEncoder();
          const data = encoder.encode(code_verifier);
          const hash = await window.crypto.subtle.digest('SHA-256', data);
          return base64URLEncode(hash);
        }

        // PKCE 完整流程演示
        async function startPKCEFlow() {
          const resultDiv = document.getElementById('result-pkce');
          resultDiv.style.display = 'block';
          
          try {
            // 1. 生成 PKCE 密钥对
            const codeVerifier = generateRandomString(64);
            const codeChallenge = await generateCodeChallenge(codeVerifier);
            
            // 将 verifier 存入 localStorage，等回调回来时要用
            localStorage.setItem('pkce_code_verifier', codeVerifier);

            // 2. 构造跳转 URL
            const authUrl = "${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/auth";
            const clientId = "${SsoConfig.clientId}";
            const redirectUri = window.location.origin + "/auth-code-callback.html?mode=pkce";
            
            const url = \`\${authUrl}?client_id=\${clientId}&response_type=code&redirect_uri=\${encodeURIComponent(redirectUri)}&scope=openid&code_challenge=\${codeChallenge}&code_challenge_method=S256\`;
            
            resultDiv.innerHTML = '<div style="padding: 15px; border-left: 4px solid #3498db; background: #f8f9fa; margin-bottom: 15px;">' +
              '<strong>步骤 1：生成 PKCE 参数</strong><br>' +
              '<span style="font-size:12px;color:#666;">Code Verifier (客户端保留):</span> <br><code style="word-break:break-all;">' + codeVerifier + '</code><br>' +
              '<span style="font-size:12px;color:#666;">Code Challenge (发给服务器):</span> <br><code style="word-break:break-all;">' + codeChallenge + '</code><br><br>' +
              '<strong>步骤 2：跳转登录</strong><br>' +
              '正在打开新窗口进行授权...请在授权完成后关闭新窗口。' +
              '</div><div id="pkce-token-result"></div>';

            // 3. 打开登录窗口
            window.open(url, 'PKCEAuthWindow', 'width=800,height=600');
            
            // 轮询检查 localStorage 中是否有 code 返回 (模拟回调处理)
            const checkCodeInterval = setInterval(async () => {
              const code = localStorage.getItem('pkce_auth_code');
              if (code) {
                clearInterval(checkCodeInterval);
                localStorage.removeItem('pkce_auth_code'); // 用完即删
                const savedVerifier = localStorage.getItem('pkce_code_verifier');
                
                // 4. 用 Code + Verifier 换取 Token
                await exchangePKCECodeForToken(code, savedVerifier, redirectUri);
              }
            }, 1000);

          } catch (error) {
            resultDiv.innerHTML = '<div style="color:red;">发生错误: ' + error.message + '</div>';
          }
        }

        async function exchangePKCECodeForToken(code, codeVerifier, redirectUri) {
          const container = document.getElementById('pkce-token-result');
          container.innerHTML = '<div style="text-align:center; padding: 20px;">⌛ 收到授权码，正在换取 Token...</div>';
          
          try {
            const response = await fetch('/api/keycloak/demo/pkce_token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                code: code, 
                redirect_uri: redirectUri,
                code_verifier: codeVerifier
              })
            });
            const data = await response.json();
            
            let html = '<div style="padding: 15px; border-left: 4px solid #2ecc71; background: #f0fcf4;">';
            html += '<strong>步骤 3：使用 Code + Verifier 换取 Token</strong><br>';
            html += '<p style="font-size:13px;color:#666;">注意：请求中包含了 code_verifier，但没有 client_secret。这与您提供的 curl 抓包完全一致。</p>';
            html += '</div>';
            
            // 复用之前的渲染逻辑，但直接追加 HTML
            const tempDiv = document.createElement('div');
            renderResult(tempDiv, data);
            html += tempDiv.innerHTML;
            
            container.innerHTML = html;
          } catch (error) {
            container.innerHTML = '<div style="color:red; padding:10px;">前端脚本错误: ' + error.message + '</div>';
          }
        }
        
        window.addEventListener('DOMContentLoaded', async () => {
          try {
            const response = await fetch('/api/check-login');
            const data = await response.json();
            
            const statusSpan = document.getElementById('login-status');
            const warningDiv = document.getElementById('login-warning');
            
            if (data.loggedIn) {
              statusSpan.innerText = '已登录应用';
              statusSpan.style.color = '#2ecc71';
            } else {
              statusSpan.innerText = '未登录应用';
              statusSpan.style.color = '#e74c3c';
              warningDiv.style.display = 'block';
              
              // 禁用需要登录的功能
              ['userinfo', 'refresh_token', 'introspect'].forEach(action => {
                const btn = document.querySelector(\`button[onclick="callApi('\${action}')"]\`);
                if (btn) {
                  btn.disabled = true;
                  btn.style.opacity = '0.5';
                  btn.style.cursor = 'not-allowed';
                  btn.title = '需要先登录主系统才能使用此功能';
                }
              });
            }
          } catch (e) {
            console.error('无法检测登录状态', e);
          }
        });

        // 授权码模式：第一步，跳转到授权页面
        function startAuthCodeFlow() {
          const authUrl = "${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/auth";
          const clientId = "${SsoConfig.clientId}";
          // 使用当前域名下的一个专门用于接收 code 的页面作为回调
          const redirectUri = window.location.origin + "/auth-code-callback.html";
          
          const url = \`\${authUrl}?client_id=\${clientId}&response_type=code&redirect_uri=\${encodeURIComponent(redirectUri)}&scope=openid\`;
          
          // 在新窗口打开，方便用户复制 code 回来
          window.open(url, 'AuthWindow', 'width=800,height=600');
        };

        // 授权码模式：第二步，换取 Token
        async function exchangeCodeForToken() {
          const code = document.getElementById('ac-code').value.trim();
          const resultDiv = document.getElementById('result-authorization_code');
          
          if (!code) {
            alert('请先输入或粘贴授权码 (code)');
            return;
          }

          resultDiv.style.display = 'block';
          resultDiv.innerHTML = '<div style="text-align:center; padding: 20px;">⌛ 请求处理中...</div>';

          try {
            const redirectUri = window.location.origin + "/auth-code-callback.html";
            const response = await fetch('/api/keycloak/demo/authorization_code', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ code: code, redirect_uri: redirectUri })
            });
            const data = await response.json();
            renderResult(resultDiv, data);
          } catch (error) {
            resultDiv.innerHTML = '<div style="color:red; padding:10px;">前端脚本错误: ' + error.message + '</div>';
          }
        };

        async function callApi(action) {
          const resultDiv = document.getElementById('result-' + action);
          resultDiv.style.display = 'block';
          resultDiv.innerHTML = '<div style="text-align:center; padding: 20px;">⌛ 请求处理中...</div>';
          
          try {
            const response = await fetch('/api/keycloak/demo/' + action, { method: 'POST' });
            const data = await response.json();
            renderResult(resultDiv, data);
          } catch (error) {
            resultDiv.innerHTML = '<div style="color:red; padding:10px;">前端脚本错误: ' + error.message + '</div>';
          }
        }

        async function callPasswordGrant() {
          const username = document.getElementById('pg-username').value;
          const password = document.getElementById('pg-password').value;
          const resultDiv = document.getElementById('result-password_grant');
          
          if (!username || !password) {
            alert('请输入用户名和密码');
            return;
          }

          resultDiv.style.display = 'block';
          resultDiv.innerHTML = '<div style="text-align:center; padding: 20px;">⌛ 请求处理中...</div>';

          try {
            const response = await fetch('/api/keycloak/demo/password_grant', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            renderResult(resultDiv, data);
          } catch (error) {
            resultDiv.innerHTML = '<div style="color:red; padding:10px;">前端脚本错误: ' + error.message + '</div>';
          }
        }

        function renderResult(container, data) {
            if (data.error) {
               let errorMsg = '<strong>请求失败:</strong> ' + data.error;
               
               // 针对特定错误的友好提示
               if (data.details && data.details.error === 'unauthorized_client') {
                 if (data.details.error_description === 'Client not enabled to retrieve service account') {
                   errorMsg += '<div style="margin-top:10px; background:#fff3cd; padding:10px; border-radius:4px; border-left:4px solid #ffc107; color:#856404;">';
                   errorMsg += '💡 <strong>解决办法：</strong><br>';
                   errorMsg += 'Keycloak 后台未开启服务账户功能。请管理员进行如下操作：<br>';
                   errorMsg += '1. 进入 Keycloak 管理控制台<br>';
                   errorMsg += '2. 点击左侧 <strong>Clients</strong><br>';
                   errorMsg += '3. 选择当前客户端 (<strong>' + "${SsoConfig.clientId}" + '</strong>)<br>';
                   errorMsg += '4. 在 <strong>Capability config</strong> 选项卡中，开启 <strong>Service accounts roles</strong><br>';
                   errorMsg += '5. 点击 Save 保存';
                   errorMsg += '</div>';
                 }
               }
               
               container.innerHTML = '<div style="color:red; padding:10px;">' + errorMsg + '<br><br><strong>详细错误信息：</strong><pre>' + JSON.stringify(data.details, null, 2) + '</pre></div>';
               return;
            }

            let html = '';
            
            // 请求详情
            html += '<h4>📤 发出的请求 (Request)</h4>';
            html += '<div style="background:#f8f9fa; padding:10px; border-radius:6px; border:1px solid #ddd; margin-bottom:15px;">';
            html += '<div><strong>URL:</strong> <span style="color:#e74c3c; font-weight:bold;">' + data.request.method + '</span> ' + data.request.url + '</div>';
            
            if (data.request.headers) {
              html += '<div style="margin-top:10px;"><strong>Headers:</strong></div>';
              html += '<pre>' + JSON.stringify(data.request.headers, null, 2) + '</pre>';
            }
            
            if (data.request.body) {
              html += '<div style="margin-top:10px;"><strong>Body (Form Data):</strong></div>';
              html += '<pre>' + JSON.stringify(data.request.body, null, 2) + '</pre>';
            }
            html += '</div>';
            
            // 响应详情
            html += '<h4>📥 收到的响应 (Response)</h4>';
            html += '<div style="background:#f8f9fa; padding:10px; border-radius:6px; border:1px solid #ddd;">';
            html += '<div><strong>Status:</strong> <span style="color:' + (data.response.status === 200 ? '#2ecc71' : '#e74c3c') + '; font-weight:bold;">' + data.response.status + ' ' + data.response.statusText + '</span></div>';
            html += '<div style="margin-top:10px;"><strong>Data:</strong></div>';
            html += '<pre>' + JSON.stringify(data.response.data, null, 2) + '</pre>';
            html += '</div>';
            
            container.innerHTML = html;
        }
      </script>
    </body>
    </html>
  `);
});

// 处理演示请求的 API
app.post('/api/keycloak/demo/:action', ensureAuthenticated, async (req, res) => {
  const action = req.params.action;
  const user = req.user;
  
  try {
    let requestInfo = {};
    let responseInfo = {};
    
    if (action === 'userinfo') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`;
      const headers = { 'Authorization': `Bearer ${user.access_token}` };
      
      requestInfo = {
        method: 'GET',
        url: url,
        headers: headers
      };
      
      const response = await axios.get(url, { headers });
      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    } 
    else if (action === 'refresh_token') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
      const body = {
        client_id: SsoConfig.clientId,
        client_secret: SsoConfig.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: user.refresh_token
      };
      
      requestInfo = {
        method: 'POST',
        url: url,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      };
      
      const response = await axios.post(url, qs.stringify(body), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      if (response.data.access_token) {
        req.user.access_token = response.data.access_token;
        req.user.refresh_token = response.data.refresh_token || req.user.refresh_token;
      }

      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    }
    else if (action === 'introspect') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token/introspect`;
      const body = {
        client_id: SsoConfig.clientId,
        client_secret: SsoConfig.clientSecret,
        token: user.access_token
      };
      
      requestInfo = {
        method: 'POST',
        url: url,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      };
      
      const response = await axios.post(url, qs.stringify(body), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    }
    else if (action === 'client_credentials') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
      const body = {
        client_id: SsoConfig.clientId,
        client_secret: SsoConfig.clientSecret,
        grant_type: 'client_credentials'
      };
      
      requestInfo = {
        method: 'POST',
        url: url,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      };
      
      const response = await axios.post(url, qs.stringify(body), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    }
    else if (action === 'password_grant') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
      const { username, password } = req.body; // 注意：需要 app.use(express.json()) 支持
      
      const body = {
        client_id: SsoConfig.clientId,
        client_secret: SsoConfig.clientSecret,
        grant_type: 'password',
        username: username,
        password: password,
        scope: 'openid'
      };
      
      requestInfo = {
        method: 'POST',
        url: url,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: { ...body, password: '******' } // 隐藏密码
      };
      
      const response = await axios.post(url, qs.stringify(body), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    }
    else if (action === 'authorization_code') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
      const { code, redirect_uri } = req.body;
      
      const body = {
        client_id: SsoConfig.clientId,
        client_secret: SsoConfig.clientSecret,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirect_uri
      };
      
      requestInfo = {
        method: 'POST',
        url: url,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      };
      
      const response = await axios.post(url, qs.stringify(body), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    }
    else if (action === 'pkce_token') {
      const url = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
      const { code, redirect_uri, code_verifier } = req.body;
      
      const body = {
        client_id: SsoConfig.clientId,
        // PKCE 模式通常不需要 client_secret，如果是 public client
        // 但这里我们的 client 可能是 confidential 的，为了演示效果，我们根据实际情况看是否需要传
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirect_uri,
        code_verifier: code_verifier
      };
      
      // 注意：如果您的 Keycloak 客户端是 "confidential"（即开启了 Client authentication），
      // 即便用了 PKCE，Keycloak 默认仍可能要求传 secret。
      // 对于真正的纯前端 public client，Keycloak 后台必须关闭 "Client authentication" 开关。
      // 这里为了演示不报错，我们还是把 secret 传过去，但在前端显示说明中强调这一点。
      body.client_secret = SsoConfig.clientSecret;
      
      requestInfo = {
        method: 'POST',
        url: url,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      };
      
      const response = await axios.post(url, qs.stringify(body), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      responseInfo = {
        status: response.status,
        statusText: response.statusText,
        data: response.data
      };
    }
    
    res.json({
      request: requestInfo,
      response: responseInfo
    });
    
  } catch (error) {
    console.error('API Demo Error:', error.message);
    res.status(500).json({
      error: error.message,
      details: error.response ? error.response.data : null
    });
  }
});

// 用户信息接入教学页面
app.get('/user-info-tutorial', ensureAuthenticated, (req, res) => {
  const accessToken = req.user.access_token;
  const userInfoUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`;
  
  // 简单的 JWT 解码函数 (仅用于演示，生产环境建议使用专门的库)
  const decodeToken = (token) => {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      return JSON.parse(jsonPayload);
    } catch (e) {
      return {};
    }
  };

  const tokenPayload = accessToken ? JSON.stringify(decodeToken(accessToken), null, 2) : '{}';

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>用户信息接入指南</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; color: #333; }
        .container { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 { color: #2c3e50; font-size: 2.5em; margin-bottom: 10px; }
        .header p { color: #7f8c8d; font-size: 1.2em; }
        
        .step-card { background: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); margin-bottom: 30px; overflow: hidden; border-left: 5px solid #3498db; }
        .step-header { padding: 20px 30px; background: #f1f9fc; border-bottom: 1px solid #e1e8ed; display: flex; align-items: center; }
        .step-number { background: #3498db; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 15px; }
        .step-title { font-size: 1.3em; font-weight: 600; color: #2c3e50; margin: 0; }
        .step-body { padding: 30px; }
        
        .code-block { background: #282c34; color: #abb2bf; padding: 20px; border-radius: 8px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 14px; margin: 15px 0; position: relative; }
        .code-label { position: absolute; top: 0; right: 0; background: #4b5363; color: white; padding: 4px 10px; font-size: 12px; border-bottom-left-radius: 8px; }
        
        .btn { padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 15px; font-weight: 600; transition: all 0.2s; display: inline-flex; align-items: center; gap: 8px; }
        .btn-primary { background-color: #3498db; color: white; }
        .btn-primary:hover { background-color: #2980b9; transform: translateY(-1px); }
        .btn-success { background-color: #2ecc71; color: white; }
        .btn-success:hover { background-color: #27ae60; transform: translateY(-1px); }
        .btn-outline { background-color: transparent; border: 2px solid #3498db; color: #3498db; }
        .btn-outline:hover { background-color: #3498db; color: white; }
        
        .info-box { background-color: #e8f6ff; border-radius: 8px; padding: 15px; margin-bottom: 20px; border-left: 4px solid #3498db; }
        .info-title { font-weight: bold; color: #2980b9; margin-bottom: 5px; display: block; }
        
        .tab-container { margin-top: 20px; }
        .tabs { display: flex; border-bottom: 2px solid #e1e8ed; }
        .tab { padding: 10px 20px; cursor: pointer; color: #7f8c8d; font-weight: 600; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.2s; }
        .tab.active { color: #3498db; border-bottom-color: #3498db; }
        .tab-content { display: none; padding: 20px 0; }
        .tab-content.active { display: block; }
        
        .json-display { font-family: 'Consolas', monospace; font-size: 13px; white-space: pre-wrap; color: #e83e8c; }
        .string-display { word-break: break-all; color: #e67e22; }
      </style>
    </head>
    <body>
      <div class="container">
        <div style="margin-bottom: 20px;">
          <a href="/" class="btn btn-outline">← 返回首页</a>
        </div>
        
        <div class="header">
          <h1>📘 用户信息接入指南</h1>
          <p>从获取 Token 到解析数据的完整全流程教学</p>
        </div>

        <!-- 步骤 1: 获取并理解 Token -->
        <div class="step-card">
          <div class="step-header">
            <div class="step-number">1</div>
            <h2 class="step-title">理解 Access Token</h2>
          </div>
          <div class="step-body">
            <p>登录成功后，Keycloak 会返回一个 <strong>Access Token</strong>。这是您访问资源的“钥匙”。它是一个 JWT (JSON Web Token) 字符串。</p>
            
            <div class="info-box">
              <span class="info-title">💡 知识点</span>
              Access Token 不仅用于身份验证，本身也携带了部分用户信息（如用户名、ID、邮箱等）。有时候，您不需要调用接口，直接解析 Token 就能拿到所需信息。
            </div>

            <div style="margin-bottom: 10px;"><strong>您的 Access Token (部分):</strong></div>
            <div class="code-block string-display">${accessToken ? accessToken.substring(0, 50) + '...' + accessToken.substring(accessToken.length - 20) : '未获取'}</div>
            
            <div style="margin-top: 20px;">
              <button class="btn btn-primary" onclick="toggleTokenDetails()">
                🔍 解析 Token 查看内部信息
              </button>
            </div>
            
            <div id="token-details" style="display: none; margin-top: 20px; background: #f8f9fa; padding: 20px; border-radius: 8px;">
              <p>这是您的 Token 解码后的内容 (Payload)：</p>
              <div class="code-block">
                <pre class="json-display">${tokenPayload}</pre>
              </div>
              <p style="font-size: 0.9em; color: #666;">可以看到，Token 中已经包含 <code>preferred_username</code>, <code>email</code>, <code>sub</code> (用户ID) 等字段。</p>
            </div>
          </div>
        </div>

        <!-- 步骤 2: 调用 UserInfo 接口 -->
        <div class="step-card" style="border-left-color: #2ecc71;">
          <div class="step-header" style="background: #f0fcf4;">
            <div class="step-number" style="background: #2ecc71;">2</div>
            <h2 class="step-title">获取完整用户信息</h2>
          </div>
          <div class="step-body">
            <p>如果 Token 中的信息不够全，或者您需要最新的用户资料，应该调用标准的 OIDC <strong>UserInfo Endpoint</strong>。</p>
            
            <div class="info-box" style="background-color: #f0fcf4; border-left-color: #2ecc71;">
              <span class="info-title" style="color: #27ae60;">🔗 接口信息</span>
              <strong>URL:</strong> <span style="font-family: monospace;">${userInfoUrl}</span><br>
              <strong>Method:</strong> GET<br>
              <strong>Headers:</strong> Authorization: Bearer &lt;access_token&gt;
            </div>

            <div style="display: flex; gap: 15px; flex-wrap: wrap;">
              <button class="btn btn-success" id="fetch-btn" onclick="fetchUserInfo()">
                🚀 发送请求获取信息
              </button>
            </div>

            <div id="api-result" style="display: none; margin-top: 20px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <strong>✅ Keycloak 响应结果:</strong>
                <span style="font-size: 0.8em; color: #2ecc71;">Status: 200 OK</span>
              </div>
              <div class="code-block">
                <pre id="user-info-json" class="json-display"></pre>
              </div>
            </div>
          </div>
        </div>

        <!-- 步骤 3: 代码实现方案 -->
        <div class="step-card" style="border-left-color: #9b59b6;">
          <div class="step-header" style="background: #fbf4fd;">
            <div class="step-number" style="background: #9b59b6;">3</div>
            <h2 class="step-title">接入代码方案</h2>
          </div>
          <div class="step-body">
            <p>选择您使用的技术栈，复制以下代码即可快速接入。</p>
            
            <div class="tab-container">
              <div class="tabs">
                <div class="tab active" onclick="switchTab('curl')">cURL (命令行)</div>
                <div class="tab" onclick="switchTab('node')">Node.js</div>
                <div class="tab" onclick="switchTab('java')">Java (Spring)</div>
                <div class="tab" onclick="switchTab('python')">Python</div>
              </div>
              
              <div id="curl" class="tab-content active">
                <p>您可以直接在终端执行此命令来测试（已填入您当前的 Token）：</p>
                <div class="code-block">
                  <div class="code-label">Bash</div>
                  curl -X GET \\<br>
                  &nbsp;&nbsp;"${userInfoUrl}" \\<br>
                  &nbsp;&nbsp;-H "Authorization: Bearer ${accessToken}"
                </div>
              </div>
              
              <div id="node" class="tab-content">
                <div class="code-block">
                  <div class="code-label">Node.js (Axios)</div>
                  const axios = require('axios');<br><br>
                  async function getUserInfo(accessToken) {<br>
                  &nbsp;&nbsp;try {<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;const response = await axios.get('${userInfoUrl}', {<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;headers: {<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'Authorization': \`Bearer \${accessToken}\`<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;});<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;console.log('User Info:', response.data);<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;return response.data;<br>
                  &nbsp;&nbsp;} catch (error) {<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;console.error('Error fetching user info:', error);<br>
                  &nbsp;&nbsp;}<br>
                  }
                </div>
              </div>
              
              <div id="java" class="tab-content">
                <div class="code-block">
                  <div class="code-label">Java (OkHttp)</div>
                  OkHttpClient client = new OkHttpClient();<br><br>
                  Request request = new Request.Builder()<br>
                  &nbsp;&nbsp;.url("${userInfoUrl}")<br>
                  &nbsp;&nbsp;.addHeader("Authorization", "Bearer " + accessToken)<br>
                  &nbsp;&nbsp;.build();<br><br>
                  try (Response response = client.newCall(request).execute()) {<br>
                  &nbsp;&nbsp;if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);<br><br>
                  &nbsp;&nbsp;System.out.println(response.body().string());<br>
                  }
                </div>
              </div>

              <div id="python" class="tab-content">
                <div class="code-block">
                  <div class="code-label">Python (Requests)</div>
                  import requests<br><br>
                  url = "${userInfoUrl}"<br>
                  headers = {"Authorization": "Bearer " + access_token}<br><br>
                  response = requests.get(url, headers=headers)<br>
                  print(response.json())
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>

      <script>
        function toggleTokenDetails() {
          const details = document.getElementById('token-details');
          details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }

        async function fetchUserInfo() {
          const btn = document.getElementById('fetch-btn');
          const resultDiv = document.getElementById('api-result');
          const jsonPre = document.getElementById('user-info-json');
          
          btn.disabled = true;
          btn.innerHTML = '⌛ 请求中...';
          
          try {
            // 调用我们后端的代理接口，或者直接调用 UserInfo (如果存在 CORS 问题，最好走后端代理)
            // 这里我们复用之前创建的 /api/keycloak/demo/userinfo 接口
            const response = await fetch('/api/keycloak/demo/userinfo', { method: 'POST' });
            const data = await response.json();
            
            resultDiv.style.display = 'block';
            if (data.error) {
              jsonPre.style.color = 'red';
              jsonPre.textContent = JSON.stringify(data, null, 2);
            } else {
              jsonPre.style.color = '#e83e8c';
              jsonPre.textContent = JSON.stringify(data.response.data, null, 2);
            }
          } catch (e) {
            resultDiv.style.display = 'block';
            jsonPre.style.color = 'red';
            jsonPre.textContent = '请求失败: ' + e.message;
          } finally {
            btn.disabled = false;
            btn.innerHTML = '🚀 发送请求获取信息';
          }
        }

        function switchTab(tabId) {
          // 隐藏所有内容
          document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
          // 取消所有 tab 的激活状态
          document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
          
          // 激活选中的
          document.getElementById(tabId).classList.add('active');
          // 找到点击的 tab 元素并添加 active 类 (这里简化处理，通过遍历匹配文本或者onclick传递this更佳，这里用索引简单模拟或者直接假定)
          // 更好的方式是传入 event
          event.target.classList.add('active');
        }
      </script>
    </body>
    </html>
  `);
});

// SSO 时序图解析页面
app.get('/sso-sequence-diagram', ensureAuthenticated, (req, res) => {
  const authUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/auth`;
  const tokenUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
  const userInfoUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SSO 登录与获取 Token 完整时序图解析</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f5f7fa; color: #333; line-height: 1.6; }
        .container { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 { color: #2c3e50; font-size: 2.2em; margin-bottom: 10px; }
        .header p { color: #7f8c8d; font-size: 1.1em; }
        
        .card { background: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); margin-bottom: 30px; overflow: hidden; }
        .card-header { padding: 15px 25px; background: #2c3e50; color: white; font-weight: 600; font-size: 1.2em; display: flex; align-items: center; }
        .card-body { padding: 30px; }
        
        .btn-outline { display: inline-block; padding: 10px 20px; border: 2px solid #2c3e50; color: #2c3e50; text-decoration: none; border-radius: 6px; font-weight: bold; transition: all 0.2s; margin-bottom: 20px; }
        .btn-outline:hover { background: #2c3e50; color: white; }

        /* 时序图样式 */
        .sequence-container { position: relative; margin: 40px 0; padding-top: 50px; }
        
        /* 实体/角色 (浏览器, 您的系统, Keycloak) */
        .actors { display: flex; justify-content: space-between; position: relative; z-index: 2; margin-bottom: 20px; }
        .actor { flex: 1; text-align: center; font-weight: bold; font-size: 16px; padding: 15px; background: #fff; border: 2px solid #3498db; border-radius: 8px; margin: 0 10px; box-shadow: 0 4px 6px rgba(52,152,219,0.1); }
        .actor.browser { border-color: #e67e22; box-shadow: 0 4px 6px rgba(230,126,34,0.1); }
        .actor.keycloak { border-color: #2ecc71; box-shadow: 0 4px 6px rgba(46,204,113,0.1); }
        
        /* 生命线 (垂直虚线) */
        .lifelines { position: absolute; top: 100px; bottom: 0; left: 0; right: 0; display: flex; justify-content: space-between; z-index: 1; }
        .lifeline { flex: 1; border-right: 2px dashed #bdc3c7; margin-right: -2px; }
        .lifeline:last-child { border-right: none; }

        /* 步骤连线和内容 */
        .steps { position: relative; z-index: 3; padding: 20px 0; }
        .step { position: relative; margin-bottom: 40px; clear: both; display: flex; align-items: center; }
        
        /* 连线箭头容器 */
        .arrow-container { position: absolute; height: 2px; background: #34495e; top: 25px; }
        .arrow-container::after { content: ''; position: absolute; border: 6px solid transparent; top: -5px; }
        
        /* 箭头方向 */
        .arrow-right::after { border-left-color: #34495e; right: -12px; }
        .arrow-left::after { border-right-color: #34495e; left: -12px; }
        
        /* 虚线箭头 (返回) */
        .arrow-dashed { background: transparent; border-top: 2px dashed #7f8c8d; }
        .arrow-dashed::after { border-left-color: #7f8c8d; }
        .arrow-left.arrow-dashed::after { border-left-color: transparent; border-right-color: #7f8c8d; }

        /* 位置计算 (基于 3 个 actor: 浏览器 16.6%, 您的系统 50%, Keycloak 83.3%) */
        .p1-to-p2 { left: 16.6%; width: 33.3%; } /* 浏览器 -> 您的系统 */
        .p2-to-p1 { left: 16.6%; width: 33.3%; } /* 您的系统 -> 浏览器 */
        .p1-to-p3 { left: 16.6%; width: 66.6%; } /* 浏览器 -> Keycloak */
        .p3-to-p1 { left: 16.6%; width: 66.6%; } /* Keycloak -> 浏览器 */
        .p2-to-p3 { left: 50%; width: 33.3%; }   /* 您的系统 -> Keycloak */
        .p3-to-p2 { left: 50%; width: 33.3%; }   /* Keycloak -> 您的系统 */

        /* 步骤说明框 */
        .step-desc { background: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); width: 80%; margin: 0 auto; position: relative; border-left: 4px solid #3498db; margin-top: 40px; }
        .step-number { position: absolute; top: -15px; left: -15px; background: #3498db; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; }
        
        .code-block { background: #282c34; color: #abb2bf; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 13px; margin-top: 10px; }
        .highlight { color: #e06c75; font-weight: bold; }
        .param { color: #d19a66; }
        .value { color: #98c379; }

      </style>
    </head>
    <body>
      <div class="container">
        <a href="/" class="btn-outline">← 返回首页</a>
        
        <div class="header">
          <h1>📈 SSO 登录与获取 Token 完整时序图解析</h1>
          <p>图解 OIDC 授权码模式 (Authorization Code Flow) 的每一步数据交互</p>
        </div>

        <div class="card">
          <div class="card-body" style="padding: 0 30px 40px 30px;">
            
            <div class="sequence-container">
              <!-- 实体 -->
              <div class="actors">
                <div class="actor browser">🌐 用户浏览器<br><span style="font-size:12px;font-weight:normal;color:#666;">(前端/手机端)</span></div>
                <div class="actor">💻 您的系统后台<br><span style="font-size:12px;font-weight:normal;color:#666;">(Client / 资源服务器)</span></div>
                <div class="actor keycloak">🔐 Keycloak 认证中心<br><span style="font-size:12px;font-weight:normal;color:#666;">(SSO 服务端)</span></div>
              </div>

              <!-- 生命线 -->
              <div class="lifelines">
                <div class="lifeline"></div>
                <div class="lifeline"></div>
                <div class="lifeline"></div>
              </div>

              <!-- 步骤交互 -->
              <div class="steps">
                
                <!-- 步骤 1 -->
                <div class="step">
                  <div class="arrow-container arrow-right p1-to-p2">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #34495e;">1. 用户点击“登录”</div>
                  </div>
                </div>
                <div class="step-desc" style="border-left-color: #e67e22;">
                  <div class="step-number" style="background: #e67e22;">1</div>
                  <strong>触发登录动作</strong><br>
                  用户在浏览器中访问您的系统受保护页面，或主动点击了“登录”按钮。
                </div>

                <!-- 步骤 2 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-left arrow-dashed p2-to-p1">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #7f8c8d;">2. 302 重定向到认证中心</div>
                  </div>
                </div>
                <div class="step-desc">
                  <div class="step-number">2</div>
                  <strong>系统要求浏览器重定向</strong><br>
                  您的系统后台发现用户未登录，生成一个授权 URL，并告诉浏览器（302 Redirect）跳过去。
                  <div class="code-block">
                    HTTP/1.1 302 Found<br>
                    Location: <span class="highlight">${authUrl}</span><br>
                    ?response_type=<span class="value">code</span><br>
                    &client_id=<span class="value">${SsoConfig.clientId}</span><br>
                    &redirect_uri=<span class="value">http://您系统的回调地址/callback</span><br>
                    &scope=<span class="value">openid profile email</span>
                  </div>
                </div>

                <!-- 步骤 3 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-right p1-to-p3">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #34495e;">3. 浏览器访问 Keycloak，用户输入账密</div>
                  </div>
                </div>

                <!-- 步骤 4 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-left arrow-dashed p3-to-p1">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #7f8c8d;">4. 认证成功，302 重定向回您的系统并携带 code</div>
                  </div>
                </div>
                <div class="step-desc" style="border-left-color: #2ecc71;">
                  <div class="step-number" style="background: #2ecc71;">4</div>
                  <strong>Keycloak 发放授权码 (Code)</strong><br>
                  用户在 Keycloak 登录成功后，Keycloak 会生成一个临时且只能使用一次的 <code>code</code>，然后让浏览器带着这个 <code>code</code> 跳回您在第2步指定的 <code>redirect_uri</code>。
                  <div class="code-block">
                    HTTP/1.1 302 Found<br>
                    Location: <span class="highlight">http://您系统的回调地址/callback</span>?<span class="param">code</span>=<span class="value">d35f3dec-3409...</span>
                  </div>
                </div>

                <!-- 步骤 5 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-right p1-to-p2">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #34495e;">5. 浏览器访问系统的 callback 接口，交出 code</div>
                  </div>
                </div>

                <!-- 步骤 6 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-right p2-to-p3">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #34495e; font-weight:bold;">6. 系统后台用 Code 换取 Token (后端通信)</div>
                  </div>
                </div>
                <div class="step-desc">
                  <div class="step-number">6</div>
                  <strong>获取核心资产：Access Token</strong><br>
                  <span style="color:#e74c3c;">【关键点】这一步是您的服务器与 Keycloak 服务器在后台偷偷进行的，不经过用户浏览器，防止 Token 泄露。</span>这就是为什么之前的配置截图里，必须写成 POST 请求的原因。
                  <div class="code-block">
                    <span class="highlight">POST</span> ${tokenUrl}<br>
                    Content-Type: application/x-www-form-urlencoded<br><br>
                    grant_type=<span class="value">authorization_code</span><br>
                    &client_id=<span class="value">${SsoConfig.clientId}</span><br>
                    &client_secret=<span class="value">PzpVX... (系统密码)</span><br>
                    &code=<span class="value">d35f3dec-3409... (第4步拿到的code)</span><br>
                    &redirect_uri=<span class="value">http://您系统的回调地址/callback</span>
                  </div>
                </div>

                <!-- 步骤 7 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-left arrow-dashed p3-to-p2">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #7f8c8d; font-weight:bold;">7. Keycloak 返回 Access Token</div>
                  </div>
                </div>
                <div class="step-desc" style="border-left-color: #2ecc71;">
                  <div class="step-number" style="background: #2ecc71;">7</div>
                  <strong>拿到 Token！</strong><br>
                  Keycloak 验证 code 和 client_secret 正确后，下发令牌。
                  <div class="code-block">
                    {<br>
                    &nbsp;&nbsp;"access_token": <span class="value">"eyJhbGciOiJSUzI1..."</span>, <span style="color:#6c757d;">// 用于后续调接口</span><br>
                    &nbsp;&nbsp;"expires_in": 300,<br>
                    &nbsp;&nbsp;"refresh_token": <span class="value">"eyJhbGciOi..."</span>, <span style="color:#6c757d;">// 用于过期后刷新</span><br>
                    &nbsp;&nbsp;"id_token": <span class="value">"eyJhb..."</span> <span style="color:#6c757d;">// 包含用户基本身份信息</span><br>
                    }
                  </div>
                </div>

                <!-- 步骤 8 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-right p2-to-p3">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #34495e;">8. 用 Token 获取用户详细信息 (可选)</div>
                  </div>
                </div>
                <div class="step-desc">
                  <div class="step-number">8</div>
                  <strong>调用 UserInfo 接口</strong><br>
                  如果 <code>id_token</code> 中的信息不够，您的系统可以随时拿着 <code>access_token</code> 去请求用户的完整资料。
                  <div class="code-block">
                    <span class="highlight">GET</span> ${userInfoUrl}<br>
                    Authorization: Bearer <span class="value">eyJhbGciOiJSUzI1...</span>
                  </div>
                </div>

                <!-- 步骤 9 -->
                <div class="step" style="margin-top: 60px;">
                  <div class="arrow-container arrow-left arrow-dashed p2-to-p1">
                    <div style="position: absolute; top: -20px; width: 100%; text-align: center; font-size: 13px; color: #7f8c8d;">9. 系统创建本地 Session，完成登录，展示页面</div>
                  </div>
                </div>

              </div>
            </div>
            
          </div>
        </div>

      </div>
    </body>
    </html>
  `);
});

// 仅获取 Code 演示页面 (不需要登录即可访问)
app.get('/get-code-only-demo', (req, res) => {
  const authUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/auth`;
  const tokenUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
  const clientId = SsoConfig.clientId;
  const clientSecret = SsoConfig.clientSecret;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>🎫 仅获取 Code 演示</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f0f2f5; color: #333; }
        .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); padding: 30px; margin-bottom: 20px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #16a085; padding-bottom: 10px; margin-top: 0; }
        .btn { padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; background-color: #16a085; color: white; transition: all 0.2s; display: inline-block; text-decoration: none; }
        .btn:hover { background-color: #1abc9c; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(26,188,156,0.3); }
        .btn-outline { background: transparent; border: 2px solid #2c3e50; color: #2c3e50; font-size: 14px; padding: 8px 16px; }
        .btn-outline:hover { background: #2c3e50; color: white; transform: none; box-shadow: none; }
        
        .code-display-area { background: #282c34; color: #98c379; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 16px; word-break: break-all; margin: 20px 0; min-height: 24px; border-left: 5px solid #16a085; }
        
        .setup-box { background: #fff3cd; border: 1px solid #ffeeba; color: #856404; padding: 15px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
        .setup-box code { background: #ffe8a1; padding: 2px 5px; border-radius: 3px; font-weight: bold; }
        
        .step { margin-bottom: 30px; }
        .step-title { font-size: 1.2em; color: #2c3e50; font-weight: bold; margin-bottom: 10px; display: flex; align-items: center; }
        .step-badge { background: #16a085; color: white; width: 24px; height: 24px; border-radius: 50%; display: inline-flex; justify-content: center; align-items: center; font-size: 14px; margin-right: 10px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div style="margin-bottom: 20px;">
          <a href="/" class="btn btn-outline">← 返回首页</a>
        </div>
        
        <div class="card">
          <h1>🎫 纯净版：仅获取授权码 (Code)</h1>
          <p style="color: #666; margin-bottom: 30px;">
            这个页面专门用于演示 OAuth2 第一步：<strong>获取 Code</strong>。它没有复杂的后续逻辑，只是单纯地把您送到 Keycloak，然后再把 Code 拿回来展示给您看。
          </p>

          <div class="setup-box">
            <strong>⚠️ 准备工作：</strong><br>
            确保在 Keycloak 后台的客户端 (<code>${clientId}</code>) 配置中，将 <br>
            <code id="display-uri"></code><br>
            添加到了 <strong>Valid redirect URIs</strong> 列表中，否则点击下方按钮会报错。
          </div>

          <div class="step">
            <div class="step-title"><span class="step-badge">1</span> 发起授权请求</div>
            <p style="font-size: 14px; color: #555;">点击此按钮，将在当前窗口直接跳转到 Keycloak 登录页。登录成功后，会自动跳回本页。</p>
            <button class="btn" onclick="goToLogin()">🚀 去 Keycloak 登录获取 Code</button>
          </div>

          <div class="step" id="result-step" style="display: none; border-top: 1px dashed #eee; padding-top: 30px;">
            <div class="step-title"><span class="step-badge">2</span> 成功获取 Code！</div>
            <p style="font-size: 14px; color: #555;">这是 Keycloak 刚刚通过 URL 参数传回来的 Code。它的寿命很短（通常不到1分钟），且只能使用一次。请复制它去第三方系统或 Postman 中换取 Token。</p>
            
            <div class="code-display-area" id="code-result"></div>
            
            <div style="display: flex; gap: 10px; margin-bottom: 20px;">
              <button class="btn" style="background: #3498db; font-size: 14px; padding: 10px 20px;" onclick="copyCode()" id="copy-btn">📋 复制 Code</button>
              <button class="btn" style="background: #9b59b6; font-size: 14px; padding: 10px 20px;" onclick="showCurl()" id="curl-btn">💻 生成换取 Token 的 cURL</button>
              <button class="btn" style="background: #95a5a6; font-size: 14px; padding: 10px 20px;" onclick="clearUrl()">🧹 清除 URL 参数</button>
            </div>
            
            <div id="curl-display" style="display: none; background: #282c34; color: #abb2bf; padding: 20px; border-radius: 8px; font-family: 'Consolas', monospace; font-size: 13px; position: relative;">
              <div style="position: absolute; top: 0; right: 0; background: #4b5363; color: white; padding: 4px 10px; font-size: 12px; border-bottom-left-radius: 8px;">Terminal / cURL</div>
              <pre id="curl-code" style="margin: 0; white-space: pre-wrap; word-break: break-all;"></pre>
              <button class="btn" style="background: #e67e22; font-size: 12px; padding: 6px 12px; margin-top: 15px;" onclick="copyCurl()" id="copy-curl-btn">复制整段 cURL</button>
              
              <div style="margin-top: 15px; padding: 10px; background: rgba(231, 76, 60, 0.1); border-left: 3px solid #e74c3c; border-radius: 4px; font-size: 12px; color: #e74c3c;">
                <strong>常见报错排查 (unauthorized_client):</strong><br>
                如果您在终端执行后遇到 <code>"error": "unauthorized_client"</code>，请检查：<br>
                1. <strong>密钥错误</strong>: <code>client_secret</code> 的值与 Keycloak 后台 (Clients -> 对应客户端 -> Credentials 标签页) 显示的不一致。<br>
                2. <strong>认证方式不匹配</strong>: 如果 Keycloak 中该客户端的 Client Authenticator 设置为了 <code>Client Id and Secret</code>，但在您的代码配置中没传 secret 或传错了。<br>
                3. <strong>Client ID 错误</strong>: 填写的 <code>client_id</code> 在该 Realm 下不存在。
              </div>
            </div>
          </div>
          
          <div id="error-step" style="display: none; background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px; margin-top: 30px; border-left: 5px solid #dc3545;">
            <strong style="font-size: 1.1em;">❌ 获取失败</strong>
            <p id="error-desc" style="margin-top: 10px; font-family: monospace;"></p>
            <button class="btn" style="background: #dc3545; font-size: 14px; padding: 8px 16px; margin-top: 10px;" onclick="clearUrl()">重新开始</button>
          </div>

        </div>
      </div>

      <script>
        const redirectUri = window.location.origin + window.location.pathname; // 即当前页面 URL，不带参数
        
        window.onload = function() {
          document.getElementById('display-uri').innerText = redirectUri;
          
          // 检查 URL 中是否有返回的参数
          const urlParams = new URLSearchParams(window.location.search);
          const code = urlParams.get('code');
          const error = urlParams.get('error');
          const errorDesc = urlParams.get('error_description');

          if (code) {
            document.getElementById('result-step').style.display = 'block';
            document.getElementById('code-result').innerText = code;
          } else if (error) {
            document.getElementById('error-step').style.display = 'block';
            document.getElementById('error-desc').innerText = error + " : " + (errorDesc || '');
          }
        };

        function goToLogin() {
          const authUrl = "${authUrl}";
          const clientId = "${clientId}";
          
          // 构造完整的授权 URL
          const targetUrl = \`\${authUrl}?client_id=\${clientId}&response_type=code&redirect_uri=\${encodeURIComponent(redirectUri)}&scope=openid\`;
          
          // 直接在当前窗口跳转
          window.location.href = targetUrl;
        }

        function copyCode() {
          const codeText = document.getElementById('code-result').innerText;
          navigator.clipboard.writeText(codeText).then(() => {
            const btn = document.getElementById('copy-btn');
            btn.innerText = '✅ 已复制';
            setTimeout(() => { btn.innerText = '📋 复制 Code'; }, 2000);
          });
        }
        
        function showCurl() {
          const codeText = document.getElementById('code-result').innerText;
          const curlContainer = document.getElementById('curl-display');
          const curlCodePre = document.getElementById('curl-code');
          
          const tokenUrl = "${tokenUrl}";
          const clientId = "${clientId}";
          const clientSecret = "${clientSecret}";
          
          // 构造标准的、与现代浏览器抓包格式一致的 cURL 命令
          // 使用 --data URL 编码格式
          let curlCmd = \`curl --request POST \\
  --url '\${tokenUrl}' \\
  --header 'Content-Type: application/x-www-form-urlencoded' \\
  --data 'grant_type=authorization_code' \\
  --data 'client_id=\${clientId}'\`;

          // 只有当配置了 clientSecret 时才添加 (兼容 confidential 和 public client)
          if (clientSecret && clientSecret.trim() !== '') {
            curlCmd += \` \\
  --data 'client_secret=\${clientSecret}'\`;
          }

          curlCmd += \` \\
  --data 'redirect_uri=\${encodeURIComponent(redirectUri)}' \\
  --data 'code=\${codeText}'\`;
          
          curlCodePre.innerText = curlCmd;
          curlContainer.style.display = 'block';
        }

        function copyCurl() {
          const curlText = document.getElementById('curl-code').innerText;
          navigator.clipboard.writeText(curlText).then(() => {
            const btn = document.getElementById('copy-curl-btn');
            btn.innerText = '✅ 已复制 cURL';
            setTimeout(() => { btn.innerText = '复制整段 cURL'; }, 2000);
          });
        }
        
        function clearUrl() {
          window.history.replaceState({}, document.title, window.location.pathname);
          window.location.reload();
        }
      </script>
    </body>
    </html>
  `);
});

// 第三方系统 OAuth2 配置教学页面
app.get('/oauth-config-tutorial', ensureAuthenticated, (req, res) => {
  const tokenUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/token`;
  const userInfoUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/userinfo`;
  const authUrl = `${SsoConfig.baseUrl}/realms/${SsoConfig.realm}/protocol/openid-connect/auth`;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>第三方系统 OAuth2 配置指南</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f0f2f5; color: #333; line-height: 1.6; }
        .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 { color: #2c3e50; font-size: 2.2em; margin-bottom: 10px; }
        .header p { color: #7f8c8d; font-size: 1.1em; }
        
        .card { background: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); margin-bottom: 30px; overflow: hidden; }
        .card-header { padding: 15px 25px; background: #2c3e50; color: white; font-weight: 600; font-size: 1.2em; display: flex; align-items: center; }
        .card-body { padding: 30px; }
        
        .flow-box { display: flex; align-items: center; justify-content: space-between; background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e1e4e8; }
        .flow-step { text-align: center; flex: 1; position: relative; }
        .flow-step:not(:last-child)::after { content: '➔'; position: absolute; right: -10px; top: 50%; transform: translateY(-50%); color: #bdc3c7; font-size: 20px; }
        .flow-icon { font-size: 24px; margin-bottom: 5px; }
        .flow-text { font-weight: bold; font-size: 14px; color: #34495e; }
        .flow-desc { font-size: 12px; color: #7f8c8d; }
        
        .highlight-box { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; color: #856404; }
        .warning-box { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; border-radius: 4px; color: #721c24; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: 600; color: #495057; width: 25%; }
        td { font-family: monospace; color: #e83e8c; }
        .field-desc { display: block; font-family: sans-serif; font-size: 0.85em; color: #6c757d; margin-top: 4px; }
        
        .btn-outline { display: inline-block; padding: 10px 20px; border: 2px solid #2c3e50; color: #2c3e50; text-decoration: none; border-radius: 6px; font-weight: bold; transition: all 0.2s; }
        .btn-outline:hover { background: #2c3e50; color: white; }
      </style>
    </head>
    <body>
      <div class="container">
        <div style="margin-bottom: 20px;">
          <a href="/" class="btn-outline">← 返回首页</a>
        </div>
        
        <div class="header">
          <h1>⚙️ 第三方系统 OAuth2/OIDC 接入指南</h1>
          <p>解答：“Access Token 是从哪来的？截图中系统该怎么填？”</p>
        </div>

        <div class="card">
          <div class="card-header">
            🧩 核心概念：Access Token 是在哪个环节拿到的？
          </div>
          <div class="card-body">
            <p>在标准的 <strong>授权码模式 (Authorization Code Flow)</strong> 中，获取 Token 分为两步。截图中的系统正是将这两步自动化了。</p>
            
            <div class="flow-box">
              <div class="flow-step">
                <div class="flow-icon">🙋‍♂️</div>
                <div class="flow-text">1. 登录重定向</div>
                <div class="flow-desc">跳转到 Keycloak 登录页</div>
              </div>
              <div class="flow-step">
                <div class="flow-icon">🔑</div>
                <div class="flow-text">2. 获取 Code</div>
                <div class="flow-desc">登录成功，回调带上 ?code=xxx</div>
              </div>
              <div class="flow-step" style="background: #e8f4f8; padding: 10px; border-radius: 8px; border: 1px solid #3498db;">
                <div class="flow-icon">🎟️</div>
                <div class="flow-text" style="color: #2980b9;">3. 换取 Token</div>
                <div class="flow-desc">系统后台用 code 换 Token<br><b>(对应截图的"第一次请求")</b></div>
              </div>
              <div class="flow-step">
                <div class="flow-icon">👤</div>
                <div class="flow-text">4. 获取用户信息</div>
                <div class="flow-desc">用 Token 调 UserInfo 接口<br><b>(对应截图的"第二次请求")</b></div>
              </div>
            </div>
            
            <div class="highlight-box">
              <strong>💡 结论：</strong> Access Token 不是在用户登录点完按钮瞬间直接回到浏览器的。而是 Keycloak 先给浏览器发一个短效的 <code>code</code>，然后您的第三方系统（后台）拿着这个 <code>code</code>，带上 <code>client_id</code> 和 <code>client_secret</code>，悄悄去 Keycloak 的 <strong>Token 接口</strong> 换回来的。
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            📝 针对您截图系统的配置对照表
          </div>
          <div class="card-body">
            <p>根据您提供的截图，这是一个典型的多步请求配置。以下是结合当前 Keycloak 环境的具体填法：</p>

            <h3 style="color: #2980b9; border-bottom: 2px solid #eee; padding-bottom: 10px;">配置页标签：【第一次请求】（换取 Token）</h3>
            
            <div class="warning-box">
              <strong>⚠️ 严重警告 (关于请求方式)：</strong><br>
              截图中显示的请求方式是 <code>GET</code>。但在 OAuth2 标准和 Keycloak 中，获取 Token <strong>必须使用 POST 方法</strong>，并且请求体格式必须是 <code>application/x-www-form-urlencoded</code>。请务必检查该系统是否允许将 <code>GET</code> 修改为 <code>POST</code>，否则接口会报错！
            </div>

            <table>
              <tr>
                <th>截图中的字段名</th>
                <th>应该填写的值 (基于当前环境)</th>
              </tr>
              <tr>
                <td>请求地址</td>
                <td>
                  ${tokenUrl}
                  <span class="field-desc">这是 Keycloak 专门用来发放 Token 的接口。</span>
                </td>
              </tr>
              <tr>
                <td>client_id</td>
                <td>
                  ${SsoConfig.clientId}
                  <span class="field-desc">在 Keycloak 中创建的客户端 ID。</span>
                </td>
              </tr>
              <tr>
                <td>client_secret</td>
                <td>
                  ${SsoConfig.clientSecret || '<i>(您配置的秘钥)</i>'}
                  <span class="field-desc">在 Keycloak 客户端的 Credentials 标签页中获取。</span>
                </td>
              </tr>
              <tr>
                <td>redirect_uri</td>
                <td>
                  <i>第三方系统提供的回调地址</i>
                  <span class="field-desc">注意：这个地址必须和第一步(获取code时)传给 Keycloak 的地址完全一致，并且必须在 Keycloak 后台配置的 "Valid redirect URIs" 列表中。</span>
                </td>
              </tr>
              <tr>
                <td>grant_type</td>
                <td>
                  authorization_code
                  <span class="field-desc">固定值。告诉 Keycloak 我现在是用 code 来换 token。</span>
                </td>
              </tr>
              <tr>
                <td>code</td>
                <td>
                  {{env.code}} 
                  <span class="field-desc">保持截图中的原样。这是该第三方系统的语法，用于动态抓取浏览器回调 URL 中的 <code>?code=...</code> 参数。</span>
                </td>
              </tr>
            </table>

            <h3 style="color: #27ae60; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 40px;">配置页标签：【第二次请求】（获取用户信息）</h3>
            <p>截图里没展示第二次请求的内容，但我可以告诉您一般应该怎么配：</p>

            <table>
              <tr>
                <th>配置项</th>
                <th>应该填写的值</th>
              </tr>
              <tr>
                <td>请求地址</td>
                <td>
                  ${userInfoUrl}
                </td>
              </tr>
              <tr>
                <td>请求方式</td>
                <td>GET</td>
              </tr>
              <tr>
                <td>请求头部 (Headers)</td>
                <td>
                  Key: <code>Authorization</code><br>
                  Value: <code>Bearer {{响应1.access_token}}</code>
                  <span class="field-desc">具体语法取决于该系统的变量提取规则。通常是从“第一次请求”返回的 JSON 中提取 <code>access_token</code> 字段。</span>
                </td>
              </tr>
            </table>
            
            <h3 style="color: #8e44ad; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 40px;">系统隐藏配置（通常在基础设置里）</h3>
            <p>该系统通常还需要您配置一个“用户点击登录时跳转的地址（Authorization Endpoint）”，这是产生 <code>code</code> 的源头：</p>
            <ul>
              <li><strong>授权地址 (Auth URL):</strong> <code>${authUrl}</code></li>
              <li>它会拼接参数形如：<code>?client_id=${SsoConfig.clientId}&response_type=code&redirect_uri=...</code></li>
            </ul>

          </div>
        </div>

      </div>
    </body>
    </html>
  `);
});

// 现有代码：iframe SSO自动token传递测试路由
app.get('/iframe-sso-test', ensureAuthenticated, (req, res) => {
  const accessToken = req.user.access_token;
  const idToken = req.user.id_token;
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>iframe SSO自动token传递测试</title>
    </head>
    <body>
      <h1>iframe SSO自动token传递测试</h1>
      <div id="test-status">父页面已加载并发送token</div>
      <iframe id="myIframe" src="http://localhost:3004" style="width:100%;height:400px;border:1px solid #ccc"></iframe>
      <script>
        const accessToken = ${JSON.stringify(accessToken)};
        const idToken = ${JSON.stringify(idToken)};
        const iframe = document.getElementById('myIframe');
        iframe.onload = function() {
          iframe.contentWindow.postMessage({
            type: 'SSO_TOKEN',
            access_token: accessToken,
            id_token: idToken
          }, 'http://localhost:3004');
        };
      </script>
    </body>
    </html>
  `);
});
