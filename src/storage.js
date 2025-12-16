const fs = require('fs');
const path = require('path');

/**
 * Abstract Storage Interface
 * All storage adapters must implement these methods.
 */
class StorageAdapter {
  async init() {}
  async read(key) { throw new Error('Not implemented'); }
  async write(key, value) { throw new Error('Not implemented'); }
  async delete(key) { throw new Error('Not implemented'); }
  async list(prefix) { throw new Error('Not implemented'); }
  async stat(key) { throw new Error('Not implemented'); } // returns { size, mtime }
  
  // Specific method for appending logs if supported, otherwise read-modify-write (inefficient)
  // For file systems, we can use append mode.
  async append(key, value) { throw new Error('Not implemented'); }
  
  // Create a write stream for streaming data directly to storage
  createWriteStream(key) { throw new Error('Not implemented'); }
}

/**
 * Local File System Implementation
 */
class FileStorage extends StorageAdapter {
  constructor(baseDir) {
    super();
    this.baseDir = baseDir;
  }

  _resolve(key) {
    // Security check to prevent directory traversal
    const safeKey = path.normalize(key).replace(/^(\.\.(\/|\\|$))+/, '');
    const p = path.join(this.baseDir, safeKey);
    if (!p.startsWith(this.baseDir)) {
       throw new Error('Access denied: Path traversal detected');
    }
    return p;
  }

  async init() {
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true });
    }
    // Ensure subdirectories we know about exist or let write() handle it?
    // Let's rely on write() ensuring dir exists or create common ones here.
    const dirs = ['history', 'logs'];
    for (const d of dirs) {
      const p = path.join(this.baseDir, d);
      if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
    }
  }

  async read(key) {
    try {
      return await fs.promises.readFile(this._resolve(key));
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
  }

  async readText(key) {
    const buf = await this.read(key);
    return buf ? buf.toString('utf-8') : null;
  }

  async readJSON(key) {
    const txt = await this.readText(key);
    return txt ? JSON.parse(txt) : null;
  }

  async write(key, value) {
    const p = this._resolve(key);
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) {
      await fs.promises.mkdir(dir, { recursive: true });
    }
    
    // Atomic write for reliability
    const temp = p + '.tmp.' + Date.now();
    const data = typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2);
    
    await fs.promises.writeFile(temp, data);
    await fs.promises.rename(temp, p);
  }

  async append(key, value) {
    const p = this._resolve(key);
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) {
      await fs.promises.mkdir(dir, { recursive: true });
    }
    await fs.promises.appendFile(p, value);
  }

  createWriteStream(key) {
    const p = this._resolve(key);
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    return fs.createWriteStream(p);
  }

  async delete(key) {
    try {
      await fs.promises.unlink(this._resolve(key));
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }

  async list(prefix) {
    // This is a simplified list for directory contents
    // Prefix is treated as a directory path relative to base
    const dir = this._resolve(prefix || '');
    try {
      const files = await fs.promises.readdir(dir);
      return files;
    } catch (e) {
      if (e.code === 'ENOENT') return [];
      throw e;
    }
  }

  async stat(key) {
    try {
      const s = await fs.promises.stat(this._resolve(key));
      return { size: s.size, mtime: s.mtimeMs };
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
  }
}

// Factory to create storage based on env
function createStorage() {
  const type = process.env.STORAGE_TYPE || 'file';
  const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
  
  console.log(`[Storage] Initializing ${type} storage at ${dataDir}`);
  
  if (type === 'file') {
    return new FileStorage(dataDir);
  }
  
  // Future: S3, Redis, etc.
  throw new Error(`Unknown storage type: ${type}`);
}

module.exports = { createStorage, FileStorage };
