#!/usr/bin/env node

/**
 * ABOUTME: Build script for the medium cybersecurity dashboard
 * ABOUTME: Optimizes assets, validates data, and prepares for deployment
 */

import { promises as fs } from 'fs';
import path from 'path';
import { RSSProcessor } from './fetch-rss.js';

const BUILD_CONFIG = {
  outputDir: './dist',
  assetsDir: './assets',
  dataDir: './data',
  sourceDir: './src',
};

class Builder {
  constructor() {
    this.startTime = Date.now();
    this.warnings = [];
    this.errors = [];
  }

  async build() {
    try {
      console.log('🏗️  Starting build process...');
      
      await this.cleanBuildDir();
      await this.validateData();
      await this.copyAssets();
      await this.optimizeAssets();
      await this.generateBuildReport();
      
      const buildTime = Date.now() - this.startTime;
      console.log(`✅ Build completed in ${(buildTime / 1000).toFixed(1)}s`);
      
      this.printSummary();
      
    } catch (error) {
      console.error('❌ Build failed:', error);
      throw error;
    }
  }

  async cleanBuildDir() {
    console.log('🧹 Cleaning build directory...');
    
    try {
      await fs.rm(BUILD_CONFIG.outputDir, { recursive: true, force: true });
      await fs.mkdir(BUILD_CONFIG.outputDir, { recursive: true });
      console.log('✅ Build directory cleaned');
    } catch (error) {
      this.warnings.push(`Failed to clean build directory: ${error.message}`);
    }
  }

  async validateData() {
    console.log('🔍 Validating data files...');
    
    try {
      // Check if data files exist
      const dataFiles = ['posts.json', 'summary.json'];
      
      for (const file of dataFiles) {
        const filePath = path.join(BUILD_CONFIG.dataDir, file);
        
        try {
          await fs.access(filePath);
          
          // Validate JSON format
          const content = await fs.readFile(filePath, 'utf8');
          JSON.parse(content);
          
          console.log(`✅ ${file} validated`);
          
        } catch (error) {
          this.errors.push(`Invalid data file ${file}: ${error.message}`);
        }
      }
      
      // Validate posts structure
      const postsPath = path.join(BUILD_CONFIG.dataDir, 'posts.json');
      const postsData = JSON.parse(await fs.readFile(postsPath, 'utf8'));
      
      if (!Array.isArray(postsData)) {
        this.errors.push('posts.json must contain an array');
      } else {
        console.log(`✅ Validated ${postsData.length} posts`);
      }
      
    } catch (error) {
      this.errors.push(`Data validation failed: ${error.message}`);
    }
  }

  async copyAssets() {
    console.log('📁 Copying assets...');
    
    try {
      // Copy main files
      const mainFiles = [
        'index.html',
        'manifest.json',
        'sw.js',
        '_headers'
      ];
      
      for (const file of mainFiles) {
        try {
          await fs.access(file);
          await fs.copyFile(file, path.join(BUILD_CONFIG.outputDir, file));
          console.log(`✅ Copied ${file}`);
        } catch (error) {
          this.warnings.push(`Failed to copy ${file}: ${error.message}`);
        }
      }
      
      // Copy directories
      const directories = ['src', 'data', 'slides'];
      
      for (const dir of directories) {
        try {
          await this.copyDirectory(dir, path.join(BUILD_CONFIG.outputDir, dir));
          console.log(`✅ Copied ${dir}/ directory`);
        } catch (error) {
          this.warnings.push(`Failed to copy ${dir}: ${error.message}`);
        }
      }
      
    } catch (error) {
      this.errors.push(`Asset copying failed: ${error.message}`);
    }
  }

  async copyDirectory(src, dest) {
    await fs.mkdir(dest, { recursive: true });
    
    const entries = await fs.readdir(src, { withFileTypes: true });
    
    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      
      if (entry.isDirectory()) {
        await this.copyDirectory(srcPath, destPath);
      } else {
        await fs.copyFile(srcPath, destPath);
      }
    }
  }

  async optimizeAssets() {
    console.log('⚡ Optimizing assets...');
    
    try {
      // Minify JSON files by removing whitespace
      const jsonFiles = await this.findFiles(BUILD_CONFIG.outputDir, '.json');
      
      for (const jsonFile of jsonFiles) {
        try {
          const content = await fs.readFile(jsonFile, 'utf8');
          const parsed = JSON.parse(content);
          const minified = JSON.stringify(parsed);
          
          // Only minify if it saves significant space (>10%)
          if (minified.length < content.length * 0.9) {
            await fs.writeFile(jsonFile, minified);
            console.log(`✅ Minified ${path.basename(jsonFile)}`);
          }
          
        } catch (error) {
          this.warnings.push(`Failed to optimize ${jsonFile}: ${error.message}`);
        }
      }
      
      // Validate HTML files
      const htmlFiles = await this.findFiles(BUILD_CONFIG.outputDir, '.html');
      
      for (const htmlFile of htmlFiles) {
        try {
          const content = await fs.readFile(htmlFile, 'utf8');
          
          // Basic HTML validation
          if (!content.includes('<!DOCTYPE html>')) {
            this.warnings.push(`${htmlFile} missing DOCTYPE declaration`);
          }
          
          if (!content.includes('<meta charset=')) {
            this.warnings.push(`${htmlFile} missing charset declaration`);
          }
          
          console.log(`✅ Validated ${path.basename(htmlFile)}`);
          
        } catch (error) {
          this.warnings.push(`Failed to validate ${htmlFile}: ${error.message}`);
        }
      }
      
    } catch (error) {
      this.errors.push(`Asset optimization failed: ${error.message}`);
    }
  }

  async findFiles(dir, extension) {
    const files = [];
    
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          const subFiles = await this.findFiles(fullPath, extension);
          files.push(...subFiles);
        } else if (entry.name.endsWith(extension)) {
          files.push(fullPath);
        }
      }
      
    } catch (error) {
      this.warnings.push(`Failed to scan directory ${dir}: ${error.message}`);
    }
    
    return files;
  }

  async generateBuildReport() {
    console.log('📊 Generating build report...');
    
    try {
      const buildInfo = {
        buildTime: new Date().toISOString(),
        buildDuration: Date.now() - this.startTime,
        errors: this.errors,
        warnings: this.warnings,
        nodeVersion: process.version,
        platform: process.platform,
      };
      
      // Get file sizes
      try {
        const stats = await this.getBuildStats();
        buildInfo.stats = stats;
      } catch (error) {
        this.warnings.push(`Failed to generate build stats: ${error.message}`);
      }
      
      await fs.writeFile(
        path.join(BUILD_CONFIG.outputDir, 'build-info.json'),
        JSON.stringify(buildInfo, null, 2)
      );
      
      console.log('✅ Build report generated');
      
    } catch (error) {
      this.warnings.push(`Failed to generate build report: ${error.message}`);
    }
  }

  async getBuildStats() {
    const stats = {
      totalFiles: 0,
      totalSize: 0,
      fileTypes: {},
    };
    
    const files = await this.findFiles(BUILD_CONFIG.outputDir, '');
    
    for (const file of files) {
      try {
        const stat = await fs.stat(file);
        const ext = path.extname(file) || 'no-extension';
        
        stats.totalFiles++;
        stats.totalSize += stat.size;
        
        if (!stats.fileTypes[ext]) {
          stats.fileTypes[ext] = { count: 0, size: 0 };
        }
        
        stats.fileTypes[ext].count++;
        stats.fileTypes[ext].size += stat.size;
        
      } catch (error) {
        this.warnings.push(`Failed to stat ${file}: ${error.message}`);
      }
    }
    
    return stats;
  }

  printSummary() {
    console.log('\n📊 Build Summary:');
    
    if (this.errors.length > 0) {
      console.log(`❌ Errors: ${this.errors.length}`);
      this.errors.forEach(error => console.log(`   ${error}`));
    }
    
    if (this.warnings.length > 0) {
      console.log(`⚠️  Warnings: ${this.warnings.length}`);
      this.warnings.forEach(warning => console.log(`   ${warning}`));
    }
    
    if (this.errors.length === 0 && this.warnings.length === 0) {
      console.log('✅ No issues found');
    }
  }
}

// Main execution
async function main() {
  try {
    const builder = new Builder();
    await builder.build();
    
    if (builder.errors.length > 0) {
      console.log('\n❌ Build completed with errors!');
      process.exit(1);
    }
    
    console.log('\n✅ Build completed successfully!');
    
  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { Builder };