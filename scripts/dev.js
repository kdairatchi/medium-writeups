#!/usr/bin/env node

/**
 * ABOUTME: Development server for the medium cybersecurity dashboard
 * ABOUTME: Provides live reloading and development features
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import { createServer } from 'http';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEV_CONFIG = {
  port: 8000,
  host: 'localhost',
  watchDirs: ['src', 'data', '.'],
  watchFiles: ['index.html', 'manifest.json', 'sw.js'],
  autoRefresh: true,
  cors: true,
};

class DevServer {
  constructor() {
    this.server = null;
    this.watchers = [];
    this.clients = new Set();
    this.isRunning = false;
  }

  async start() {
    try {
      console.log('🚀 Starting development server...');
      
      await this.createServer();
      await this.setupWatchers();
      
      this.isRunning = true;
      console.log(`✅ Development server running at http://${DEV_CONFIG.host}:${DEV_CONFIG.port}`);
      console.log(`📁 Serving files from: ${process.cwd()}`);
      
      if (DEV_CONFIG.autoRefresh) {
        console.log('🔄 Auto-refresh enabled');
      }
      
      this.printHelp();
      
    } catch (error) {
      console.error('❌ Failed to start development server:', error);
      throw error;
    }
  }

  async createServer() {
    this.server = createServer(async (req, res) => {
      try {
        await this.handleRequest(req, res);
      } catch (error) {
        console.error('Request error:', error);
        res.writeHead(500);
        res.end('Internal Server Error');
      }
    });
    
    this.server.listen(DEV_CONFIG.port, DEV_CONFIG.host);
  }

  async handleRequest(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    let filePath = url.pathname;
    
    // Handle CORS
    if (DEV_CONFIG.cors) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }
    
    // Handle OPTIONS requests
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
    
    // Default to index.html for root
    if (filePath === '/') {
      filePath = '/index.html';
    }
    
    // Special endpoints
    if (filePath === '/dev-status') {
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(200);
      res.end(JSON.stringify({
        status: 'running',
        uptime: process.uptime(),
        clients: this.clients.size,
        autoRefresh: DEV_CONFIG.autoRefresh,
      }));
      return;
    }
    
    if (filePath === '/dev-refresh' && DEV_CONFIG.autoRefresh) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.writeHead(200);
      
      this.clients.add(res);
      
      req.on('close', () => {
        this.clients.delete(res);
      });
      
      return;
    }
    
    // Serve static files
    await this.serveStaticFile(filePath, res);
  }

  async serveStaticFile(filePath, res) {
    try {
      // Remove leading slash and resolve path
      const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
      const fullPath = path.resolve(cleanPath);
      
      // Security check - ensure file is within project directory
      const projectRoot = process.cwd();
      if (!fullPath.startsWith(projectRoot)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }
      
      // Check if file exists
      await fs.access(fullPath);
      
      const stat = await fs.stat(fullPath);
      
      if (stat.isDirectory()) {
        // Try to serve index.html from directory
        const indexPath = path.join(fullPath, 'index.html');
        try {
          await fs.access(indexPath);
          return this.serveStaticFile(path.relative(process.cwd(), indexPath), res);
        } catch {
          res.writeHead(404);
          res.end('Directory listing not supported');
          return;
        }
      }
      
      // Determine content type
      const ext = path.extname(fullPath).toLowerCase();
      const contentType = this.getContentType(ext);
      
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Length', stat.size);
      
      // Inject auto-refresh script for HTML files
      if (ext === '.html' && DEV_CONFIG.autoRefresh) {
        const content = await fs.readFile(fullPath, 'utf8');
        const injectedContent = this.injectRefreshScript(content);
        
        res.setHeader('Content-Length', Buffer.byteLength(injectedContent));
        res.writeHead(200);
        res.end(injectedContent);
      } else {
        res.writeHead(200);
        const stream = (await import('fs')).createReadStream(fullPath);
        stream.pipe(res);
      }
      
      console.log(`📄 Served: ${filePath} (${this.formatSize(stat.size)})`);
      
    } catch (error) {
      if (error.code === 'ENOENT') {
        res.writeHead(404);
        res.end('File not found');
        console.log(`❌ Not found: ${filePath}`);
      } else {
        res.writeHead(500);
        res.end('Internal Server Error');
        console.error(`❌ Error serving ${filePath}:`, error.message);
      }
    }
  }

  getContentType(ext) {
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css',
      '.js': 'application/javascript',
      '.json': 'application/json',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon',
      '.woff': 'font/woff',
      '.woff2': 'font/woff2',
      '.ttf': 'font/ttf',
      '.eot': 'application/vnd.ms-fontobject',
    };
    
    return types[ext] || 'application/octet-stream';
  }

  injectRefreshScript(html) {
    const script = `
    <script>
    (function() {
      const eventSource = new EventSource('/dev-refresh');
      eventSource.onmessage = function(event) {
        if (event.data === 'refresh') {
          console.log('🔄 File changed, refreshing...');
          window.location.reload();
        }
      };
      
      eventSource.onerror = function() {
        console.log('🔌 Lost connection to dev server, retrying...');
        setTimeout(() => window.location.reload(), 1000);
      };
      
      console.log('🔄 Auto-refresh connected');
    })();
    </script>
    `;
    
    // Insert before closing </body> tag, or at the end if no </body>
    if (html.includes('</body>')) {
      return html.replace('</body>', script + '</body>');
    } else {
      return html + script;
    }
  }

  async setupWatchers() {
    if (!DEV_CONFIG.autoRefresh) return;
    
    const { watch } = await import('fs');
    
    // Watch directories
    for (const dir of DEV_CONFIG.watchDirs) {
      try {
        await fs.access(dir);
        
        const watcher = watch(dir, { recursive: true }, (eventType, filename) => {
          if (filename) {
            console.log(`🔄 File changed: ${filename}`);
            this.broadcastRefresh();
          }
        });
        
        this.watchers.push(watcher);
        console.log(`👁️  Watching: ${dir}/`);
        
      } catch (error) {
        console.log(`⚠️  Cannot watch directory ${dir}: ${error.message}`);
      }
    }
    
    // Watch individual files
    for (const file of DEV_CONFIG.watchFiles) {
      try {
        await fs.access(file);
        
        const watcher = watch(file, (eventType) => {
          console.log(`🔄 File changed: ${file}`);
          this.broadcastRefresh();
        });
        
        this.watchers.push(watcher);
        console.log(`👁️  Watching: ${file}`);
        
      } catch (error) {
        console.log(`⚠️  Cannot watch file ${file}: ${error.message}`);
      }
    }
  }

  broadcastRefresh() {
    for (const client of this.clients) {
      try {
        client.write('data: refresh\\n\\n');
      } catch (error) {
        this.clients.delete(client);
      }
    }
  }

  formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  printHelp() {
    console.log('\\n📋 Available commands:');
    console.log('  Ctrl+C         Stop the server');
    console.log('  npm run fetch  Update RSS data');
    console.log('  npm run build  Build for production');
    console.log('  npm run test   Run tests');
    console.log('\\n🌐 Endpoints:');
    console.log(`  http://localhost:${DEV_CONFIG.port}/          Main dashboard`);
    console.log(`  http://localhost:${DEV_CONFIG.port}/slides/   Presentation mode`);
    console.log(`  http://localhost:${DEV_CONFIG.port}/dev-status Development status`);
  }

  async stop() {
    console.log('\\n🛑 Stopping development server...');
    
    this.isRunning = false;
    
    // Close all watchers
    this.watchers.forEach(watcher => watcher.close());
    this.watchers = [];
    
    // Close all SSE connections
    for (const client of this.clients) {
      try {
        client.end();
      } catch (error) {
        // Ignore errors when closing connections
      }
    }
    this.clients.clear();
    
    // Close server
    if (this.server) {
      this.server.close();
    }
    
    console.log('✅ Development server stopped');
  }
}

// Main execution
async function main() {
  const devServer = new DevServer();
  
  // Handle graceful shutdown
  process.on('SIGINT', async () => {
    await devServer.stop();
    process.exit(0);
  });
  
  process.on('SIGTERM', async () => {
    await devServer.stop();
    process.exit(0);
  });
  
  try {
    await devServer.start();
  } catch (error) {
    console.error('❌ Failed to start development server:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { DevServer };