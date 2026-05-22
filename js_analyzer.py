# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Focused JavaScript analysis with strict endpoint filtering to reduce noise.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import JMenuItem, JMenu
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter
from java.lang import Thread

import sys
import os
import re
import inspect
import base64
import binascii
import math

# Add extension directory to path
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel


# ==================== ENDPOINT PATTERNS ====================
# Focus on high-value API endpoints only

ENDPOINT_PATTERNS = [
    # API endpoints
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/grpc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/soap[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/rpc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/json-rpc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Versioned API endpoints
    re.compile(r'["\'](/v[0-9]+(?:\.[0-9]+)?/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v[0-9]+(?:\.[0-9]+)?/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/version/[0-9]+/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),

    # OAuth/Auth endpoints
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/authorize[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/authenticate[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/register[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/signup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/signin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/signout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/callback[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/refresh[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/sso[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/saml[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/openid[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Sensitive paths - Extended
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/secret[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/secure[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/hidden[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/test[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/staging[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dev[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/prod[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/uat[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/qa[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Data management endpoints
    re.compile(r'["\'](/data[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/database[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/db[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/export[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/import[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/migrate[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/sql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # File operations
    re.compile(r'["\'](/file[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/files[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/document[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/documents[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/archive[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/static/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/media/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/assets/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),

    # User management endpoints
    re.compile(r'["\'](/user[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/users[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/account[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/accounts[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/profile[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/profiles[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/member[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/members[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/customer[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/customers[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # System/Admin operations
    re.compile(r'["\'](/system[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/server[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/servers[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/status[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/health[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/metrics[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/monitoring[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logs[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logging[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/console[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/shell[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/terminal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Payment/Transaction endpoints
    re.compile(r'["\'](/payment[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/payments[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/transaction[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/transactions[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/billing[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/invoice[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/invoices[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/checkout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Webhook endpoints
    re.compile(r'["\'](/webhook[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/webhooks[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/hook[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/hooks[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/callback/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/notify[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/notification[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Well-known paths - Extended
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.git/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.svn/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.hg/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),

    # Framework-specific endpoints
    re.compile(r'["\'](/actuator[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),  # Spring Boot
    re.compile(r'["\'](/rails[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),  # Ruby on Rails
    re.compile(r'["\'](/wp-[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-content/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-admin/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-includes/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-json/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress REST API

    # Development/Testing endpoints
    re.compile(r'["\'](/swagger[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/openapi[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/docs[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/documentation[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/redoc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/playground[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/explorer[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Search endpoints
    re.compile(r'["\'](/search[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/query[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/lookup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # External service integrations
    re.compile(r'["\'](/slack[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/discord[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/github[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/gitlab[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/bitbucket[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/stripe[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/paypal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Email endpoints
    re.compile(r'["\'](/email[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/mail[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/newsletter[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/subscribe[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/unsubscribe[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # API Gateway patterns
    re.compile(r'["\'](/gateway[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/proxy[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/route[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Cache endpoints
    re.compile(r'["\'](/cache[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/flush[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/purge[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Queue/Job endpoints
    re.compile(r'["\'](/queue[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/job[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/jobs[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/task[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/tasks[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Database specific endpoints (for admin tools)
    re.compile(r'["\'](/phpmyadmin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/adminer[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/pgadmin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/mongodb[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # File extension patterns for sensitive files
    re.compile(r'["\'](.*\.(?:git|svn|hg|bak|old|backup|swp))["\']', re.IGNORECASE),
    re.compile(r'["\'](.*\.(?:sql|dump|tar|gz|zip|7z|rar))["\']', re.IGNORECASE),
    re.compile(r'["\'](.*\.(?:env|config|conf|ini|properties|yml|yaml|json))["\']', re.IGNORECASE),

    # --- ENHANCED PATTERNS ---
    # Relative paths (more aggressive)
    re.compile(r'["\'](/[a-zA-Z0-9_-]{3,}/[a-zA-Z0-9/_-]{3,})["\']'),
    re.compile(r'["\'](/[a-zA-Z0-9_-]{3,}\.php|\.aspx|\.asp|\.jsp|\.json)["\']', re.IGNORECASE),
    
    # JS fetch/axios/ajax calls
    re.compile(r'(?:fetch|axios|get|post|put|delete|request)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(?:url|path|endpoint|uri)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
    
    # Template literals (partial match)
    re.compile(r'`(/[^`]+)`'),

    # --- BROAD RELATIVE PATHS ---
    re.compile(r'["\'](/[a-zA-Z0-9_\-\.\/\?\#]{2,})["\']'),
    
    # Template strings and modern JS variations
    re.compile(r'\$\{[`"\']?(/[^`"\']+)[`"\']?\}'),
    re.compile(r'(?:get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']', re.IGNORECASE),
    re.compile(r'(?:url|path|endpoint|uri|href)\s*[:=]\s*[`"\']([^`"\']+)[`"\']', re.IGNORECASE),
    re.compile(r'\.action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
]

# LinkFinder fallback regex (very broad)
LINKFINDER_PATTERN = re.compile(
    r'(?:"|\')'                                 # Start delimiter
    r'('                                        # Group 1
    r'((?:[a-zA-Z]{1,10}://|//)[^"\'/]{1,}\.[a-zA-Z]{2,}[^"\'><]{0,})' # Full URL
    r'|'
    r'((?:/|\.\.?/)[^"\'><,;| *()(%%$^!]{1,})'  # Relative path
    r'|'
    r'([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"\'><]{0,}|))' # File with extension
    r'|'
    r'([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"\'><]{0,}|))' # Generic path
    r')'
    r'(?:"|\')'                                 # End delimiter
)

# URL patterns - full URLs
URL_PATTERNS = [
    # Standard URL patterns
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ftp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ftps://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ws://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ssh://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](telnet://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](smtp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ldap://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ldaps://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](mongo://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](mongodb(?:\+srv)?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](redis://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](rediss://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](postgres(?:ql)?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](mysql://[^\s"\'<>]{10,})["\']'),
    
    # Cloud storage - Extended
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://s3-[a-zA-Z0-9-]+\.amazonaws\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3-website-[a-zA-Z0-9-]+\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.file\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.queue\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.table\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://firebasestorage\.googleapis\.com/[^\s"\'<>]*)'),
    
    # Cloud services URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.execute-api\.[a-zA-Z0-9.-]+\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.lambda-url\.[a-zA-Z0-9.-]+\.on\.aws[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfront\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.azurewebsites\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.appspot\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfunctions\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.run\.app[^\s"\'<>]*)'),
    
    # Database URLs with credentials
    re.compile(r'(https?://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(postgres(?:ql)?://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(mysql://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(redis://:[^\s"\'<>]*@[^\s"\'<>]+)'),
    
    # Internal/Private network URLs
    re.compile(r'(https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[^\s"\'<>]+)'),
    re.compile(r'(https?://localhost[^\s"\'<>]*)'),
    re.compile(r'(https?://127\.0\.0\.1[^\s"\'<>]*)'),
    re.compile(r'(https?://\[::1\][^\s"\'<>]*)'),
    re.compile(r'(https?://(?:local|dev|test|staging|uat)\.[^\s"\'<>]+)'),
    
    # API Gateway/Proxy URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/v[0-9]+/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/api/v[0-9]+/[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.[^\s"\'<>]+)'),
    re.compile(r'(https?://graphql\.[^\s"\'<>]+)'),
    re.compile(r'(https?://rest\.[^\s"\'<>]+)'),
    
    # Authentication/Identity URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/oauth/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/auth/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/login[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/\.well-known/[^\s"\'<>]*)'),
    re.compile(r'(https?://accounts\.[^\s"\'<>]+)'),
    re.compile(r'(https?://auth\.[^\s"\'<>]+)'),
    re.compile(r'(https?://sso\.[^\s"\'<>]+)'),
    re.compile(r'(https?://identity\.[^\s"\'<>]+)'),
    
    # Monitoring/Logging URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/metrics[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/health[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/status[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/debug[^\s"\'<>]*)'),
    re.compile(r'(https?://grafana\.[^\s"\'<>]+)'),
    re.compile(r'(https?://prometheus\.[^\s"\'<>]+)'),
    re.compile(r'(https?://kibana\.[^\s"\'<>]+)'),
    re.compile(r'(https?://elk\.[^\s"\'<>]+)'),
    
    # Admin/Management URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/admin[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/dashboard[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/console[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/phpmyadmin[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/pgadmin[^\s"\'<>]*)'),
    re.compile(r'(https?://admin\.[^\s"\'<>]+)'),
    re.compile(r'(https?://dashboard\.[^\s"\'<>]+)'),
    re.compile(r'(https?://manager\.[^\s"\'<>]+)'),
    
    # CI/CD/DevOps URLs
    re.compile(r'(https?://jenkins\.[^\s"\'<>]+)'),
    re.compile(r'(https?://gitlab\.[^\s"\'<>]+)'),
    re.compile(r'(https?://github\.[^\s"\'<>]+)'),
    re.compile(r'(https?://bitbucket\.[^\s"\'<>]+)'),
    re.compile(r'(https?://circleci\.[^\s"\'<>]+)'),
    re.compile(r'(https?://travis-ci\.[^\s"\'<>]+)'),
    re.compile(r'(https?://drone\.[^\s"\'<>]+)'),
    re.compile(r'(https?://argo\.[^\s"\'<>]+)'),
    
    # Documentation/API Docs URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/docs[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/swagger[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/openapi[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/redoc[^\s"\'<>]*)'),
    re.compile(r'(https?://docs\.[^\s"\'<>]+)'),
    re.compile(r'(https?://api-docs\.[^\s"\'<>]+)'),
    
    # Webhook/Notification URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/webhook[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/hook[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/callback[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/notify[^\s"\'<>]*)'),
    re.compile(r'(https?://webhook\.[^\s"\'<>]+)'),
    
    # File/Storage URLs with sensitive extensions
    re.compile(r'(https?://[^\s"\'<>]*\.(?:git|svn|hg)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:bak|old|backup|swp)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:sql|dump)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:tar|gz|zip|7z|rar)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:env|config|conf|ini)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:pem|key|cer|crt|pfx)[^\s"\'<>]*)'),
    
    # Mail/Email URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/mail[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/email[^\s"\'<>]*)'),
    re.compile(r'(https?://mail\.[^\s"\'<>]+)'),
    re.compile(r'(https?://smtp\.[^\s"\'<>]+)'),
    re.compile(r'(https?://imap\.[^\s"\'<>]+)'),
    re.compile(r'(https?://pop\.[^\s"\'<>]+)'),
    
    # Message Queue/Broker URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/rabbitmq[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/kafka[^\s"\'<>]*)'),
    re.compile(r'(https?://rabbitmq\.[^\s"\'<>]+)'),
    re.compile(r'(https?://kafka\.[^\s"\'<>]+)'),
    re.compile(r'(https?://mq\.[^\s"\'<>]+)'),
    
    # Cache URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/redis[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/memcached[^\s"\'<>]*)'),
    re.compile(r'(https?://redis\.[^\s"\'<>]+)'),
    re.compile(r'(https?://memcached\.[^\s"\'<>]+)'),
    re.compile(r'(https?://cache\.[^\s"\'<>]+)'),
    
    # Testing/Staging URLs
    re.compile(r'(https?://(?:test|staging|uat|qa|dev|preprod)\.[^\s"\'<>]+)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.test[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.staging[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+-test[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+-staging[^\s"\'<>]*)'),
    
    # CDN URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfront\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.akamaihd\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.fastly\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cdn\.cloudflare\.net[^\s"\'<>]*)'),
    
    # Analytics/Tracking URLs
    re.compile(r'(https?://analytics\.[^\s"\'<>]+)'),
    re.compile(r'(https?://stats\.[^\s"\'<>]+)'),
    re.compile(r'(https?://metrics\.[^\s"\'<>]+)'),
    re.compile(r'(https?://tracking\.[^\s"\'<>]+)'),
    
    # Payment/Checkout URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/checkout[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/payment[^\s"\'<>]*)'),
    re.compile(r'(https?://checkout\.[^\s"\'<>]+)'),
    re.compile(r'(https?://payment\.[^\s"\'<>]+)'),
    re.compile(r'(https?://pay\.[^\s"\'<>]+)'),
    
    # Third-party service URLs
    re.compile(r'(https?://hooks\.slack\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://discord\.com/api/webhooks[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.telegram\.org[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.whatsapp\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.stripe\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.paypal\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.twilio\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.sendgrid\.com[^\s"\'<>]*)'),
    
    # Generic suspicious URL patterns
    re.compile(r'(https?://[^\s"\'<>]*[=&?](?:password|token|key|secret|auth)=[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\?(?:[^&\s]*&){3,}[^\s"\'<>]*)'),  # URLs with many parameters
    re.compile(r'(https?://[^\s"\'<>]*@[^\s"\'<>]+)'),  # URLs with username/password
    
    # IP address URLs (not in private ranges)
    re.compile(r'(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s"\'<>]*)'),
    
    # Shortened/obfuscated URLs
    re.compile(r'(https?://[a-zA-Z0-9]{6,12}\.[a-zA-Z]{2,6}[^\s"\'<>]*)'),  # Short domain names
    re.compile(r'(https?://[a-f0-9]{8,}\.[a-zA-Z]{2,6}[^\s"\'<>]*)'),  # Hex domain names
]

# Secret patterns
SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16,20})'), "AWS Access Key"),
    (re.compile(r'(ASIA[0-9A-Z]{16,20})'), "AWS Temporary Access Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35,45})'), "Google API Key"),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Secret Key"),
    (re.compile(r'(gh[pousr]_[0-9a-zA-Z]{36,})'), "GitHub Token"),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token"),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'), "JWT"),
    (re.compile(r'(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)'), "Private Key"),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'\<>{}\[\]]+)'), "MongoDB URI"),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'\<>{}\[\]]+)'), "PostgreSQL URI"),
    
    # Cloud Provider Secrets - Extended
    (re.compile(r'(AZURE_CLIENT_SECRET[=\s:]+["\']?[0-9a-zA-Z\-_]{40,}["\']?)'), "Azure Client Secret"),
    (re.compile(r'(DefaultAzureCredential[=\s:]+["\']?[0-9a-zA-Z\-_]{40,}["\']?)'), "Azure Default Credential"),
    (re.compile(r'(heroku_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'), "Heroku API Key"),
    (re.compile(r'(digitalocean_[0-9a-f]{64})'), "DigitalOcean Token"),
    (re.compile(r'(linode_token[=\s:]+["\']?[0-9a-f]{64}["\']?)'), "Linode Token"),
    (re.compile(r'(vultr_api_key[=\s:]+["\']?[0-9a-f]{64}["\']?)'), "Vultr API Key"),
    (re.compile(r'(gcp_service_account[=\s:]+["\']?[0-9a-zA-Z\-_]{24,}["\']?)'), "GCP Service Account"),
    
    # Payment Processors - Extended
    (re.compile(r'(sk_test_[0-9a-zA-Z]{24,})'), "Stripe Test Secret Key"),
    (re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Publishable Key"),
    (re.compile(r'(rk_live_[0-9a-zA-Z]{24,})'), "Razorpay Live Key"),
    (re.compile(r'(rk_test_[0-9a-zA-Z]{24,})'), "Razorpay Test Key"),
    (re.compile(r'(paypal_client_id[=\s:]+["\']?[A-Za-z0-9_]{80,}["\']?)'), "PayPal Client ID"),
    (re.compile(r'(paypal_client_secret[=\s:]+["\']?[A-Za-z0-9_]{80,}["\']?)'), "PayPal Client Secret"),
    (re.compile(r'(square_access_token[=\s:]+["\']?EAAA[0-9a-zA-Z\-_]{80,}["\']?)'), "Square Access Token"),
    (re.compile(r'(braintree_private_key[=\s:]+["\']?[0-9a-zA-Z]{32}["\']?)'), "Braintree Private Key"),
    
    # Social Media/Platforms - Extended
    (re.compile(r'(twitter[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z]{25,}["\']?)'), "Twitter API Key"),
    (re.compile(r'(twitter[-\s]?api[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z]{50,}["\']?)'), "Twitter API Secret"),
    (re.compile(r'(facebook[-\s]?app[-\s]?secret[=\s:]+["\']?[0-9a-f]{32,}["\']?)'), "Facebook App Secret"),
    (re.compile(r'(facebook[-\s]?access[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{200,}["\']?)'), "Facebook Access Token"),
    (re.compile(r'(discord[-\s]?bot[-\s]?token[=\s:]+["\']?[A-Za-z0-9\.\-_]{59,}["\']?)'), "Discord Bot Token"),
    (re.compile(r'(discord[-\s]?client[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z\-_]{32}["\']?)'), "Discord Client Secret"),
    (re.compile(r'(instagram[-\s]?access[-\s]?token[=\s:]+["\']?[0-9a-f]{200,}["\']?)'), "Instagram Access Token"),
    (re.compile(r'(linkedin[-\s]?client[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z]{16}["\']?)'), "LinkedIn Client Secret"),
    (re.compile(r'(reddit[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z\-_]{30,}["\']?)'), "Reddit Secret"),
    
    # Communication Services - Extended
    (re.compile(r'(twilio[-\s]?account[-\s]?sid[=\s:]+["\']?AC[0-9a-f]{32}["\']?)'), "Twilio Account SID"),
    (re.compile(r'(twilio[-\s]?auth[-\s]?token[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "Twilio Auth Token"),
    (re.compile(r'(sendgrid[-\s]?api[-\s]?key[=\s:]+["\']?SG\.[0-9a-zA-Z\-_]{66,}["\']?)'), "SendGrid API Key"),
    (re.compile(r'(nexmo[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{8}["\']?)'), "Nexmo/Vonage API Key"),
    (re.compile(r'(nexmo[-\s]?api[-\s]?secret[=\s:]+["\']?[0-9a-f]{16}["\']?)'), "Nexmo/Vonage API Secret"),
    (re.compile(r'(plivo[-\s]?auth[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{40}["\']?)'), "Plivo Auth Token"),
    (re.compile(r'(messagebird[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z]{25}["\']?)'), "MessageBird API Key"),
    
    # CI/CD & DevOps
    (re.compile(r'(dockerhub[-\s]?token[=\s:]+["\']?[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?)'), "DockerHub Token"),
    (re.compile(r'(circleci[-\s]?token[=\s:]+["\']?[0-9a-f]{40}["\']?)'), "CircleCI Token"),
    (re.compile(r'(travisci[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{22,}["\']?)'), "Travis CI Token"),
    (re.compile(r'(jenkins[-\s]?token[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "Jenkins Token"),
    (re.compile(r'(gitlab[-\s]?token[=\s:]+["\']?glpat-[0-9a-zA-Z\-_]{20,}["\']?)'), "GitLab Personal Access Token"),
    (re.compile(r'(bitbucket[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{64}["\']?)'), "Bitbucket Token"),
    (re.compile(r'(npm[-\s]?token[=\s:]+["\']?npm_[0-9a-zA-Z\-_]{36}["\']?)'), "NPM Token"),
    (re.compile(r'(pypi[-\s]?token[=\s:]+["\']?pypi-[0-9a-zA-Z\-_]{40,}["\']?)'), "PyPI Token"),
    
    # Modern Platforms
    (re.compile(r'(clerk[-\s]?api[-\s]?key[=\s:]+["\']?sk_(?:live|test)_[a-zA-Z0-9]{32,}["\']?)'), "Clerk API Key"),
    (re.compile(r'(supabase[-\s]?anon[-\s]?key[=\s:]+["\']?eyJ[a-zA-Z0-9\._\-]{100,}["\']?)'), "Supabase Anon Key"),
    (re.compile(r'(supabase[-\s]?service[-\s]?role[=\s:]+["\']?eyJ[a-zA-Z0-9\._\-]{100,}["\']?)'), "Supabase Service Role"),
    (re.compile(r'(vercel[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{24}["\']?)'), "Vercel Token"),
    
    # Database & Storage
    (re.compile(r'(redis://:[^\s@]+@[^\s"\']+)'), "Redis URI with Password"),
    (re.compile(r'(redis[-\s]?password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "Redis Password"),
    (re.compile(r'(mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+)'), "MySQL URI with Credentials"),
    (re.compile(r'(mysql[-\s]?password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "MySQL Password"),
    (re.compile(r'(cassandra[-\s]?password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "Cassandra Password"),
    (re.compile(r'(amazonaws\.com/[^\s"\']*[=\s:]+["\']?[0-9a-zA-Z/+]{40,})'), "AWS S3/CloudFront"),
    (re.compile(r'(firebase[-\s]?api[-\s]?key[=\s:]+["\']?AIza[0-9A-Za-z\-_]{35}["\']?)'), "Firebase API Key"),
    (re.compile(r'(firebase[-\s]?database[-\s]?url[=\s:]+["\']?https://[^\s"\']+firebaseio\.com["\']?)'), "Firebase Database URL"),
    
    # Monitoring & Analytics
    (re.compile(r'(newrelic[-\s]?license[-\s]?key[=\s:]+["\']?[0-9a-f]{40}["\']?)'), "New Relic License Key"),
    (re.compile(r'(sentry[-\s]?dsn[=\s:]+["\']?https://[0-9a-f]{32}@[^\s"\']+["\']?)'), "Sentry DSN"),
    (re.compile(r'(datadog[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "Datadog API Key"),
    (re.compile(r'(splunk[-\s]?token[=\s:]+["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?)'), "Splunk Token"),
    
    # Email Services
    (re.compile(r'(mailgun[-\s]?api[-\s]?key[=\s:]+["\']?key-[0-9a-f]{32}["\']?)'), "Mailgun API Key"),
    (re.compile(r'(ses[-\s]?smtp[-\s]?password[=\s:]+["\']?[0-9a-zA-Z/+]{20,}["\']?)'), "AWS SES SMTP Password"),
    (re.compile(r'(sparkpost[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{40}["\']?)'), "SparkPost API Key"),
    (re.compile(r'(postmark[-\s]?server[-\s]?token[=\s:]+["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?)'), "Postmark Server Token"),
    (re.compile(r'(mailchimp[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{32}-us[0-9]{1,2}["\']?)'), "Mailchimp API Key"),
    
    # ===== AI/ML Service Keys =====
    (re.compile(r'(sk-[a-zA-Z0-9]{20,})'), "OpenAI API Key"),
    (re.compile(r'(sk-ant-[a-zA-Z0-9\-]{90,})'), "Anthropic API Key"),
    (re.compile(r'(hf_[a-zA-Z0-9]{34})'), "HuggingFace Token"),
    (re.compile(r'(r8_[a-zA-Z0-9]{40})'), "Replicate API Token"),
    
    # ===== Auth Providers =====
    (re.compile(r'(auth0[-_]?client[-_]?secret\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{32,}["\']?)', re.IGNORECASE), "Auth0 Client Secret"),
    (re.compile(r'(okta[-_]?api[-_]?token\s*[=:]\s*["\']?[0-9a-zA-Z_\-]{42}["\']?)', re.IGNORECASE), "Okta API Token"),
    (re.compile(r'(cognito[-_]?client[-_]?secret\s*[=:]\s*["\']?[a-zA-Z0-9]{52}["\']?)', re.IGNORECASE), "AWS Cognito Client Secret"),
    
    # ===== Infrastructure =====
    (re.compile(r'(hvs\.[a-zA-Z0-9_\-]{24,})'), "HashiCorp Vault Token"),
    (re.compile(r'(consul[-_]?token\s*[=:]\s*["\']?[0-9a-f\-]{36}["\']?)', re.IGNORECASE), "Consul Token"),
    (re.compile(r'(DO_API_TOKEN\s*[=:]\s*["\']?[a-f0-9]{64}["\']?)'), "DigitalOcean API Token"),
    
    # ===== Crypto/Blockchain =====
    (re.compile(r'(0x[a-fA-F0-9]{64})'), "Ethereum Private Key"),
    
    # ===== DNS/CDN Providers =====
    (re.compile(r'(cloudflare[-_]?api[-_]?key\s*[=:]\s*["\']?[0-9a-f]{37}["\']?)', re.IGNORECASE), "Cloudflare API Key"),
    (re.compile(r'(fastly[-_]?api[-_]?token\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{32}["\']?)', re.IGNORECASE), "Fastly API Token"),
    
    # ===== Messaging =====
    (re.compile(r'([0-9]{8,10}:[a-zA-Z0-9_\-]{35})'), "Telegram Bot Token"),
    
    # ===== AWS Secret Access Key =====
    (re.compile(r'(?:aws)?[-_]?secret[-_]?(?:access)?[-_]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', re.IGNORECASE), "AWS Secret Access Key"),
    
    # ===== Passwords in Code =====
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{6,60})["\']', re.IGNORECASE), "Hardcoded Password"),
    (re.compile(r'(?:db[-_]?pass|database[-_]?password)\s*[=:]\s*["\']([^"\'\s]{6,60})["\']', re.IGNORECASE), "Database Password"),
    
    # ===== Connection Strings =====
    (re.compile(r'((?:jdbc|odbc):[a-zA-Z0-9:/@._\-]+)', re.IGNORECASE), "JDBC/ODBC Connection String"),
    (re.compile(r'(Server=[^;]+;.*(?:Password|Pwd)=[^;]+)', re.IGNORECASE), "ADO.NET Connection String"),
    
    # ===== Generic Patterns (deduplicated) =====
    (re.compile(r'(?:api[-\s_]?key|auth[-\s_]?token|access[-\s_]?token|secret[-\s_]?key|app[-\s_]?key|session[-\s_]?id|user[-\s_]?token)[=\s:]+["\']?([0-9a-zA-Z\-_]{16,})["\']?', re.IGNORECASE), "Sensitive Assignment Pattern"),
    (re.compile(r'["\']([a-zA-Z0-9\-_]{40,})["\']'), "High-Entropy String Token"),
]

# Secret Severity Classification
SECRET_SEVERITY = {
    "Private Key": "CRITICAL", "AWS Access Key": "CRITICAL", "AWS Temporary Access Key": "CRITICAL",
    "AWS Secret Access Key": "CRITICAL", "MongoDB URI": "CRITICAL", "PostgreSQL URI": "CRITICAL",
    "MySQL URI with Credentials": "CRITICAL", "Redis URI with Password": "CRITICAL",
    "Ethereum Private Key": "CRITICAL", "Hardcoded Password": "CRITICAL",
    "Database Password": "CRITICAL", "JDBC/ODBC Connection String": "CRITICAL",
    "ADO.NET Connection String": "CRITICAL", "AWS Cognito Client Secret": "CRITICAL",
    "Stripe Live Secret Key": "HIGH", "GitHub Token": "HIGH", "GitHub PAT": "HIGH",
    "Slack Token": "HIGH", "JWT": "HIGH", "JWT Token": "HIGH",
    "Google API Key": "HIGH", "OpenAI API Key": "HIGH", "Anthropic API Key": "HIGH",
    "HuggingFace Token": "HIGH", "Replicate API Token": "HIGH",
    "HashiCorp Vault Token": "HIGH", "Telegram Bot Token": "HIGH",
    "Auth0 Client Secret": "HIGH", "Okta API Token": "HIGH", "Consul Token": "HIGH",
    "Cloudflare API Key": "HIGH", "Fastly API Token": "HIGH",
    "DigitalOcean API Token": "HIGH", "Twilio Auth Token": "HIGH",
    "SendGrid API Key": "HIGH", "Twilio Account SID": "HIGH",
    "Stripe Test Secret Key": "MEDIUM", "Stripe Live Publishable Key": "MEDIUM",
    "Firebase API Key": "MEDIUM", "Supabase Anon Key": "MEDIUM",
    "Sensitive Assignment Pattern": "MEDIUM", "High-Entropy String Token": "LOW",
}


# Cloud Patterns
CLOUD_PATTERNS = [
    (re.compile(r'([a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com)'), "AWS S3 Bucket"),
    (re.compile(r'([a-z0-9.-]+\.blob\.core\.windows\.net)'), "Azure Blob Storage"),
    (re.compile(r'([a-z0-9.-]+\.file\.core\.windows\.net)'), "Azure File Storage"),
    (re.compile(r'([a-z0-9.-]+\.queue\.core\.windows\.net)'), "Azure Queue Storage"),
    (re.compile(r'([a-z0-9.-]+\.table\.core\.windows\.net)'), "Azure Table Storage"),
    (re.compile(r'(storage\.googleapis\.com/[a-z0-9.-]+)'), "Google Cloud Storage"),
    (re.compile(r'([a-z0-9.-]+\.storage\.googleapis\.com)'), "Google Cloud Storage Bucket"),
]

# Subdomain Pattern - Only match within quotes to avoid JS code noise
SUBDOMAIN_PATTERN = re.compile(r'["\'](([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,10})["\']')

# Valid TLDs for subdomain filtering
VALID_TLDS = {
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ai', 'ly',
    'app', 'dev', 'info', 'biz', 'icu', 'me', 'tv', 'xyz', 'cloud', 'aws',
    'online', 'site', 'tech', 'store', 'shop', 'blog', 'inc', 'agency',
    'us', 'uk', 'ca', 'de', 'fr', 'jp', 'cn', 'in', 'ru', 'br', 'au', 'eu'
}

# Keyword Patterns for Mining
KEYWORD_PATTERNS = [
    re.compile(r'(\b(?:api_?key|secret|token|password|admin|auth|creds|credential|login|config|env|internal|private|root)\b)', re.IGNORECASE),
    re.compile(r'(\b(?:sourceMappingURL|sourceURL)\b)'),
]

# Email pattern
EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# File patterns - detect references to sensitive file types
# Compact set-based approach (replaces 490-line mega-regex)
SENSITIVE_EXTENSIONS = {
    'sql', 'db', 'sqlite', 'sqlite3', 'mdb', 'csv', 'tsv', 'xlsx', 'xls',
    'json', 'jsonl', 'xml', 'yaml', 'yml', 'toml', 'avro', 'parquet',
    'conf', 'config', 'cfg', 'ini', 'env', 'properties', 'settings',
    'log', 'htaccess', 'htpasswd', 'bak', 'backup', 'old', 'orig', 'tmp', 'swp',
    'key', 'pem', 'crt', 'cer', 'csr', 'der', 'p12', 'pfx', 'jks', 'gpg',
    'doc', 'docx', 'pdf', 'ppt', 'pptx', 'odt', 'rtf',
    'zip', 'tar', 'gz', 'tgz', 'bz2', 'rar', '7z', 'war', 'jar',
    'sh', 'bash', 'bat', 'cmd', 'ps1', 'vbs', 'py', 'rb', 'pl', 'php',
    'tf', 'tfstate', 'tfvars', 'hcl', 'dump', 'export', 'pcap',
    'asp', 'aspx', 'jsp', 'cgi',
    'dockerignore', 'dockerfile',
    'kubeconfig', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    'known_hosts', 'authorized_keys',
}

_ext_pattern = '|'.join(sorted(SENSITIVE_EXTENSIONS))

FILE_PATTERNS = [
    # Files with sensitive extensions
    re.compile(r'["\']([a-zA-Z0-9_/.-]+\.(?:' + _ext_pattern + r'))["\']', re.IGNORECASE),
    # Dot-files (config, credentials, etc.)
    re.compile(r'["\'](\.(?:env|gitignore|htaccess|htpasswd|bashrc|bash_profile|npmrc|yarnrc|dockerignore|editorconfig|gitconfig|netrc|pgpass|pypirc|condarc|git-credentials|ssh|aws|kube|docker)[a-zA-Z0-9._/-]*)["\']', re.IGNORECASE),
    # Files with sensitive keywords in name
    re.compile(r'["\']([a-zA-Z0-9_/.-]*(?:password|credential|secret|token|private|backup|dump|config|admin|database|shadow|master|deploy)[a-zA-Z0-9_/.-]*\.[a-zA-Z0-9]+)["\']', re.IGNORECASE),
    # Version control / sensitive directory traversals
    re.compile(r'["\'](\.(?:git|svn|hg)/[^\s"\']+)["\']', re.IGNORECASE),
    # Unix sensitive paths
    re.compile(r'["\'](/etc/(?:passwd|shadow|hosts|group|sudoers|crontab|nginx|apache2|ssh|ssl)[^\s"\']*)["\']'),
    re.compile(r'["\'](/var/log/[^\s"\']+|/tmp/[^\s"\']+|/root/[^\s"\']+|/home/[^/]+/\.[^\s"\']+)["\']'),
    # Windows executables/sensitive
    re.compile(r'["\']([A-Za-z]:\\[^\s"\']+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|reg))["\']', re.IGNORECASE),
    # Version/backup files
    re.compile(r'["\']([a-zA-Z0-9_/.-]+\.(?:v\d+|_\d{8}|-\d{8}|\d{14}|\d{8}))["\']', re.IGNORECASE),
    # Source maps
    re.compile(r'["\']([a-zA-Z0-9_/.-]+\.map)["\']', re.IGNORECASE),
]

# ===== NEW DETECTION CATEGORIES =====

# DOM Sink Patterns (XSS-relevant dangerous functions)
DOM_SINK_PATTERNS = [
    (re.compile(r'\.(innerHTML|outerHTML)\s*='), "DOM XSS Sink: innerHTML/outerHTML"),
    (re.compile(r'document\.write\s*\('), "DOM XSS Sink: document.write"),
    (re.compile(r'\beval\s*\('), "Dangerous Function: eval()"),
    (re.compile(r'\bFunction\s*\('), "Dangerous Function: Function()"),
    (re.compile(r'setTimeout\s*\(\s*["\']'), "Dangerous Function: setTimeout(string)"),
    (re.compile(r'setInterval\s*\(\s*["\']'), "Dangerous Function: setInterval(string)"),
    (re.compile(r'\.insertAdjacentHTML\s*\('), "DOM XSS Sink: insertAdjacentHTML"),
    (re.compile(r'\$\s*\(.*\)\.html\s*\('), "jQuery XSS Sink: .html()"),
    (re.compile(r'\blocation\s*=|location\.href\s*='), "Potential Open Redirect"),
    (re.compile(r'window\.open\s*\('), "Potential Open Redirect: window.open"),
    (re.compile(r'\.setAttribute\s*\(\s*["\'](?:href|src|action)["\']'), "DOM Attribute Sink"),
    (re.compile(r'\.createContextualFragment\s*\('), "DOM XSS Sink: createContextualFragment"),
    (re.compile(r'\.srcdoc\s*='), "DOM XSS Sink: srcdoc"),
    (re.compile(r'postMessage\s*\('), "postMessage (verify origin check)"),
]

# CORS Misconfiguration Patterns
CORS_PATTERNS = [
    (re.compile(r'Access-Control-Allow-Origin\s*:\s*\*', re.IGNORECASE), "CORS Wildcard Origin"),
    (re.compile(r'Access-Control-Allow-Credentials\s*:\s*true', re.IGNORECASE), "CORS Allow Credentials"),
    (re.compile(r'cors\s*:\s*\{[^}]*origin\s*:\s*true', re.IGNORECASE), "CORS Permissive Config"),
    (re.compile(r'Access-Control-Allow-Headers\s*:\s*\*', re.IGNORECASE), "CORS Wildcard Headers"),
]

# Hardcoded IP Patterns
IP_PATTERN = re.compile(r'["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?)["\']')

# Comment Mining Patterns (developer info leaks)
COMMENT_PATTERNS = [
    re.compile(r'(?://|/\*|#)\s*(TODO|FIXME|HACK|XXX|BUG|SECURITY|VULN|TEMP|DEPRECATED|WARNING)[\s:]+([^\n*]{5,120})', re.IGNORECASE),
]


# ==================== NOISE FILTERS ====================
# Extensive list of patterns to EXCLUDE

# Domains to exclude from URLs (XML namespaces, standards, etc.)
NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

# Path prefixes that indicate module imports (NOT real endpoints)
MODULE_PREFIXES = (
    './', '../', '.../', 
    './lib', '../lib', './utils', '../utils',
    './node_modules', '../node_modules',
    './src', '../src', './dist', '../dist',
)

# Patterns that are clearly internal JS/build artifacts
NOISE_PATTERNS = [
    # Module/library imports
    re.compile(r'^\.\.?/'),  # Starts with ./ or ../
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),  # Locale files: en.js, en-gb.js
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),  # Just locale: en, en-gb
    re.compile(r'-xform$'),  # Excel xform modules
    re.compile(r'^sha\d*$'),  # sha, sha1, sha256
    re.compile(r'^aes$|^des$|^md5$'),  # Crypto modules
    
    # MIME Types and Technical Noise
    re.compile(r'^(?:text|application|image|audio|video|font|model|message)/[a-zA-Z0-9\-\.\+]+$', re.IGNORECASE),
    re.compile(r'^[A-Z][a-zA-Z0-9]+/[A-Z][a-zA-Z0-9]+$'), # Etc/UTC, Africa/Cairo
    re.compile(r'^iPhone$|^iPod$|^iPad$|^Android$|^Windows$|^Linux$|^Macintosh$', re.IGNORECASE),
    re.compile(r'^utf-8$|^ascii$|^iso-8859-1$', re.IGNORECASE),
    re.compile(r'^GET$|^POST$|^PUT$|^DELETE$|^PATCH$|^OPTIONS$|^HEAD$'), # HTTP Methods
    re.compile(r'^[a-z0-9]{32}$|^[a-z0-9]{40}$|^[a-z0-9]{64}$'), # Hashes with no context
    
    # PDF internal structure
    re.compile(r'^/[A-Z][a-z]+\s'),  # /Type /Font, /Filter /Standard
    re.compile(r'^/[A-Z][a-z]+$'),  # /Parent, /Kids, /Resources
    re.compile(r'^\d+ \d+ R$'),  # PDF object references
    
    # Excel/XML internal paths
    re.compile(r'^xl/'),  # Excel internal
    re.compile(r'^docProps/'),  # Document properties
    re.compile(r'^_rels/'),  # Relationships
    re.compile(r'^META-INF/'),  # Manifest
    re.compile(r'\.xml$'),  # XML files
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    
    # Build/bundler artifacts
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    
    # Generic noise
    re.compile(r'^\+'),  # Starts with +
    re.compile(r'^\$\{'),  # Template literal
    re.compile(r'^#'),  # Fragment only
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),  # Single letter paths
    re.compile(r'^/[A-Z]$'),  # Single letter paths
    re.compile(r'^http://$'),  # Empty http://
    re.compile(r'_ngcontent'),  # Angular internals
]

# Specific strings to exclude
NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    """JS Analyzer with noise-reduced endpoint detection."""
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("JS Analyzer")
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Results storage
        self.all_findings = []
        self.seen_values = set()
        self.source_map = {}  # Store source body by name
        
        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self._log("JS Analyzer loaded - Right-click JS responses to analyze")
    
    def _log(self, msg):
        self._stdout.println("[JS Analyzer] " + str(msg))
    
    def getTabCaption(self):
        return "JS Analyzer"
    
    def getUiComponent(self):
        return self.panel
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                # Main Menu
                main_menu = JMenu("JS Analyzer")
                
                # Analyze All
                all_item = JMenuItem("Analyze All")
                all_item.addActionListener(AnalyzeAction(self, invocation, "all"))
                main_menu.add(all_item)
                
                main_menu.addSeparator()
                
                # Selective modes
                categories = [
                    ("Endpoints Only", "endpoints"),
                    ("Secrets Only", "secrets"),
                    ("URLs Only", "urls"),
                    ("Subdomains Only", "subdomains"),
                    ("Cloud Storage Only", "cloud"),
                    ("Emails & Files", "emails_files"),
                    ("DOM Sinks & Security", "dom_sinks"),
                ]
                
                for label, mode in categories:
                    item = JMenuItem(label)
                    item.addActionListener(AnalyzeAction(self, invocation, mode))
                    main_menu.add(item)
                
                menu.add(main_menu)
        except Exception as e:
            self._log("Menu error: " + str(e))
        return menu
    
    def analyze_response(self, message_info, mode="all"):
        """Analyze a response with deep pre-processing and error handling."""
        try:
            response = message_info.getResponse()
            if not response:
                return
            
            # Get source URL
            try:
                req_info = self._helpers.analyzeRequest(message_info)
                url = str(req_info.getUrl())
                source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
                if len(source_name) > 40:
                    source_name = source_name[:40] + "..."
            except:
                url = "Unknown"
                source_name = "Unknown"
            
            # Get response body
            resp_info = self._helpers.analyzeResponse(response)
            body_offset = resp_info.getBodyOffset()
            raw_body = self._helpers.bytesToString(response[body_offset:])
            
            if len(raw_body) < 50:
                return
            
            self._log("Analyzing (%s): %s" % (mode, source_name))
            self.panel.set_progress("Analyzing: %s..." % source_name)
            
            # Pre-process body to decode escapes (\uXXXX, \xXX)
            # This is critical for discovery in minified JS
            body = self._preprocess_body(raw_body)
            
            new_findings = []
            skipped_count = 0
            
            # Store source body for later viewing 
            # Use full URL to avoid collisions when different sites have same filename
            self.source_map[url] = body
            
            # Determine what to run
            run_endpoints = mode in ["all", "endpoints"]
            run_urls = mode in ["all", "urls"]
            run_secrets = mode in ["all", "secrets"]
            run_emails = mode in ["all", "emails_files"]
            run_files = mode in ["all", "emails_files"]
            run_cloud = mode in ["all", "cloud"]
            run_subdomains = mode in ["all", "subdomains"]
            run_keywords = mode in ["all", "keywords"] or mode == "all"
            run_dom_sinks = mode in ["all", "dom_sinks"]
            
            # --- PHASE 1: Endpoints (Specific + Broad) ---
            if run_endpoints:
                try:
                    all_patterns = ENDPOINT_PATTERNS + [LINKFINDER_PATTERN]
                    for pattern in all_patterns:
                        for match in pattern.finditer(body):
                            value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                            if self._is_valid_endpoint(value):
                                category = self._get_best_category(value) if pattern == LINKFINDER_PATTERN else "endpoints"
                                detail = self._decode_base64(value)
                                finding = self._add_finding(category, value, url, match.start(1) if match.lastindex else match.start(0), detail, source_name)
                                if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("Endpoint Pass Failed: %s" % str(e))

            # --- PHASE 2: URLs ---
            if run_urls or mode == "all":
                try:
                    for pattern in URL_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                            if self._is_valid_url(value):
                                finding = self._add_finding("urls", value, url, match.start(1) if match.lastindex else match.start(0), self._decode_base64(value), source_name)
                                if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("URL Pass Failed: %s" % str(e))
            
            # --- PHASE 3: Secrets (with severity classification) ---
            if run_secrets or mode == "all":
                try:
                    for pattern, secret_type in SECRET_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                            if self._is_valid_secret(value):
                                entropy = self._calculate_entropy(value)
                                decoded = self._decode_base64(value)
                                severity = SECRET_SEVERITY.get(secret_type, "MEDIUM")
                                detail = "[%s] %s (Entropy: %.2f)" % (severity, secret_type, entropy)
                                if decoded: detail += " | Decoded: %s" % decoded
                                finding = self._add_finding("secrets", value, url, match.start(1) if match.lastindex else match.start(0), detail, source_name)
                                if finding:
                                    finding["severity"] = severity
                                    new_findings.append(finding)
                except Exception as e:
                    self._log("Secret Pass Failed: %s" % str(e))
            
            # --- PHASE 4: Emails ---
            if run_emails or mode == "all":
                try:
                    for match in EMAIL_PATTERN.finditer(body):
                        value = match.group(1).strip()
                        if self._is_valid_email(value):
                            finding = self._add_finding("emails", value, url, match.start(1), "", source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("Email Pass Failed: %s" % str(e))
            
            # --- PHASE 5: Files ---
            if run_files or mode == "all":
                try:
                    for pattern in FILE_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                            if self._is_valid_file(value):
                                finding = self._add_finding("files", value, url, match.start(1) if match.lastindex else match.start(0), "", source_name)
                                if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("File Pass Failed: %s" % str(e))
            
            # --- PHASE 6: Cloud Storage ---
            if run_cloud or mode == "all":
                try:
                    for pattern, cloud_type in CLOUD_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(1).strip()
                            finding = self._add_finding("cloud", value, url, match.start(1), cloud_type, source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("Cloud Pass Failed: %s" % str(e))

            # --- PHASE 7: Subdomains ---
            if run_subdomains or mode == "all":
                try:
                    for match in SUBDOMAIN_PATTERN.finditer(body):
                        value = match.group(1).strip()
                        if self._is_valid_subdomain(value):
                            finding = self._add_finding("subdomains", value, url, match.start(1), "", source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("Subdomain Pass Failed: %s" % str(e))

            # --- PHASE 8: Keywords ---
            if run_keywords or mode == "all":
                try:
                    for pattern in KEYWORD_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(1).strip()
                            finding = self._add_finding("keywords", value, url, match.start(1), "", source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("Keyword Pass Failed: %s" % str(e))

            # --- PHASE 9: DOM Sinks (XSS/Security) ---
            if mode == "all":
                try:
                    for pattern, sink_type in DOM_SINK_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(0).strip()[:120]
                            finding = self._add_finding("dom_sinks", value, url, match.start(), sink_type, source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("DOM Sink Pass Failed: %s" % str(e))

            # --- PHASE 10: CORS Misconfigurations ---
            if mode == "all":
                try:
                    for pattern, cors_type in CORS_PATTERNS:
                        for match in pattern.finditer(body):
                            value = match.group(0).strip()[:120]
                            finding = self._add_finding("dom_sinks", value, url, match.start(), cors_type, source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("CORS Pass Failed: %s" % str(e))

            # --- PHASE 11: Hardcoded IPs ---
            if mode == "all":
                try:
                    for match in IP_PATTERN.finditer(body):
                        value = match.group(1).strip()
                        if self._is_valid_ip(value):
                            finding = self._add_finding("endpoints", value, url, match.start(1), "Hardcoded IP Address", source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("IP Pass Failed: %s" % str(e))

            # --- PHASE 12: Comment Mining (Developer Info Leaks) ---
            if mode == "all":
                try:
                    for pattern in COMMENT_PATTERNS:
                        for match in pattern.finditer(body):
                            tag = match.group(1).upper()
                            comment_text = match.group(2).strip()
                            value = "[%s] %s" % (tag, comment_text)
                            finding = self._add_finding("keywords", value, url, match.start(), "Developer Comment", source_name)
                            if finding: new_findings.append(finding)
                except Exception as e:
                    self._log("Comment Mining Pass Failed: %s" % str(e))

            # Final UI Update
            self.panel.set_progress("")
            if new_findings:
                self._log("Analysis Complete: %d items found." % len(new_findings))
                self.panel.add_findings(new_findings, source_name)
            else:
                self._log("No findings found in source.")
                
        except Exception as e:
            self._log("Analysis Crashed: %s" % str(e))
            import traceback
            traceback.print_exc(file=sys.stderr)
    
    def _add_finding(self, category, value, url, offset=0, detail="", source_name=""):
        """Add a finding with global deduplication and metadata mapping."""
        key = str(category) + ":" + str(value)
        if key in self.seen_values:
            return None
            
        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source_name, # display name (filename)
            "url": url,           # full key for source_map (URL)
            "offset": offset,
            "detail": detail
        }
        self.all_findings.append(finding)
        return finding
    
    def _preprocess_body(self, body):
        """Decode Unicode and Hex escapes in JS body for deep discovery."""
        if not body: return ""
        def decode_unicode(match):
            try: return unichr(int(match.group(1), 16)) if sys.version_info[0] < 3 else chr(int(match.group(1), 16))
            except: return match.group(0)
        body = re.sub(r'\\u([0-9a-fA-F]{4})', decode_unicode, body)
        def decode_hex(match):
            try: return unichr(int(match.group(1), 16)) if sys.version_info[0] < 3 else chr(int(match.group(1), 16))
            except: return match.group(0)
        body = re.sub(r'\\x([0-9a-fA-F]{2})', decode_hex, body)
        return body

    def _decode_base64(self, value):
        """Attempt to decode base64 if it looks like useful text."""
        if not value or len(value) < 8 or not re.match(r'^[A-Za-z0-9+/=]+$', value):
            return None
        try:
            if len(value) % 4 != 0: return None
            decoded = base64.b64decode(value)
            if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded):
                return decoded.decode('utf-8', 'ignore')
        except: pass
        return None

    def _is_static_noise(self, value):
        """Universal filter for static asset noise."""
        if not value: return True
        static_regex = r'\.(?:png|jpg|jpeg|gif|svg|webp|ico|css|scss|woff2?|ttf|eot|otf|bmp|mp3|mp4|avi|mov|wmv|flv|swf|exe|zip|rar|7z|tar|gz|iso|dmg|bin|apk|msi|map|pdf|docx?|xlsx?|pptx?)([?#].*)?$'
        return bool(re.search(static_regex, value, re.IGNORECASE))

    def _calculate_entropy(self, text):
        """Calculate Shannon Entropy using frequency counting (optimized)."""
        if not text: return 0
        length = float(len(text))
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    def _is_valid_endpoint(self, value):
        if not value or len(value) < 3 or self._is_static_noise(value): return False
        
        # Explicitly filter out JS/Source Map/Static files from "Endpoints"
        # These belong in "Files" or "URLs", not API endpoints
        val_lower = value.lower()
        
        # Strip query parameters and fragments for extension check
        clean_val = val_lower.split('?')[0].split('#')[0]
        
        if clean_val.endswith('.js') or clean_val.endswith('.map') or clean_val.endswith('.css') or \
           clean_val.endswith('.png') or clean_val.endswith('.svg') or clean_val.endswith('.ico') or \
           clean_val.endswith('.woff') or clean_val.endswith('.woff2') or clean_val.endswith('.ttf'):
            return False
            
        if any(x in val_lower for x in ['w3.org', 'schema.org', 'xmlns:', 'utf-8']): return False
        if '/' in value or '\\' in value or value.startswith('.'):
            for pattern in NOISE_PATTERNS:
                if pattern.search(value): return False
            return True
        return False

    def _is_valid_secret(self, value):
        if not value or len(value) < 10 or self._is_static_noise(value): return False
        val_lower = value.lower()
        if any(x in val_lower for x in ['example', 'placeholder', 'your-', 'xxxx', 'test', 'function(', 'return']): return False
        # Entropy & Character diversity check
        entropy = self._calculate_entropy(value)
        if len(value) > 20 and entropy < 3.5: return False
        if len(set(value)) < 7: return False
        return True

    def _is_valid_url(self, value):
        if not value or len(value) < 15 or self._is_static_noise(value): return False
        val_lower = value.lower()
        for domain in NOISE_DOMAINS:
            if domain in val_lower: return False
        return '://' in value or value.startswith('//')

    def _is_valid_subdomain(self, value):
        if not value or len(value) < 5 or self._is_static_noise(value): return False
        parts = value.lower().split('.')
        if len(parts) < 2 or parts[-1] not in VALID_TLDS: return False
        # Ignore common JS noise
        noise = {'parse','stringify','push','pop','shift','unshift','length','prototype','window','document','on','bs','min','max'}
        if any(p in noise for p in parts): return False
        return True

    def _is_valid_email(self, value):
        if not value or '@' not in value or self._is_static_noise(value): return False
        domain = value.split('@')[-1].lower()
        if domain in {'example.com', 'test.com'} or 'noreply' in value.lower(): return False
        return True

    def _is_valid_ip(self, value):
        """Validate IP address - filter private/loopback ranges."""
        if not value: return False
        ip = value.split(':')[0]  # Remove port
        parts = ip.split('.')
        if len(parts) != 4: return False
        try:
            octets = [int(p) for p in parts]
            if any(o < 0 or o > 255 for o in octets): return False
            # Filter private/loopback/link-local
            if octets[0] == 10: return False
            if octets[0] == 127: return False
            if octets[0] == 172 and 16 <= octets[1] <= 31: return False
            if octets[0] == 192 and octets[1] == 168: return False
            if octets[0] == 169 and octets[1] == 254: return False
            if octets[0] == 0 or octets[0] == 255: return False
            return True
        except:
            return False

    def _is_valid_file(self, value):
        if not value or len(value) < 3: return False
        val_lower = value.lower()
        if any(x in val_lower for x in ['node_modules', '.min.', 'chunk', 'bundle', 'webpack', 'polyfill']): return False
        # Use SENSITIVE_EXTENSIONS set for O(1) lookup
        ext = val_lower.rsplit('.', 1)[-1] if '.' in val_lower else ''
        if ext in SENSITIVE_EXTENSIONS: return True
        # Also check dot-files
        if val_lower.startswith('.'): return True
        return False

    def _get_best_category(self, value):
        val_lower = value.lower()
        if val_lower.startswith('http') or val_lower.startswith('//'): return "urls"
        if any(val_lower.endswith(ext) for ext in ['.js', '.json', '.php', '.sql', '.bak']): return "files"
        return "endpoints"

    def get_source_code(self, source_name):
        return self.source_map.get(source_name, "")
    
    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()
        self.source_map = {}
        
    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation, mode="all"):
        self.extender = extender
        self.invocation = invocation
        self.mode = mode
    
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        for msg in messages:
            runner = AnalysisRunner(self.extender, msg, self.mode)
            runner.start()


class AnalysisRunner(Thread):
    """Jython-compatible background thread for analysis."""
    def __init__(self, extender, message, mode):
        Thread.__init__(self)
        self.extender = extender
        self.message = message
        self.mode = mode
        self.setDaemon(True)
    
    def run(self):
        try:
            self.extender.analyze_response(self.message, self.mode)
        except Exception as e:
            self.extender._log("Analysis thread error: %s" % str(e))
