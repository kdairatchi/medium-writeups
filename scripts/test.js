#!/usr/bin/env node

/**
 * ABOUTME: Test runner for the medium cybersecurity dashboard
 * ABOUTME: Validates RSS processing, data integrity, and security features
 */

import { promises as fs } from 'fs';
import path from 'path';
import { RSSProcessor, CONFIG } from './fetch-rss.js';

// Test configuration
const TEST_CONFIG = {
  testDataDir: './test-data',
  maxTestFeeds: 3, // Limit to avoid rate limiting during tests
  timeout: 10000,
};

class TestRunner {
  constructor() {
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
    this.errors = [];
  }

  addTest(name, testFn) {
    this.tests.push({ name, testFn });
  }

  async runTest(test) {
    try {
      console.log(`🧪 Running: ${test.name}`);
      await test.testFn();
      console.log(`✅ Passed: ${test.name}`);
      this.passed++;
      return true;
    } catch (error) {
      console.log(`❌ Failed: ${test.name} - ${error.message}`);
      this.errors.push({ test: test.name, error: error.message });
      this.failed++;
      return false;
    }
  }

  async runAll() {
    console.log('🚀 Starting test suite...\n');
    
    for (const test of this.tests) {
      await this.runTest(test);
    }
    
    this.printSummary();
    return this.failed === 0;
  }

  printSummary() {
    console.log('\n📊 Test Summary:');
    console.log(`✅ Passed: ${this.passed}`);
    console.log(`❌ Failed: ${this.failed}`);
    console.log(`📈 Success Rate: ${((this.passed / this.tests.length) * 100).toFixed(1)}%`);
    
    if (this.errors.length > 0) {
      console.log('\n⚠️  Failures:');
      this.errors.forEach(error => {
        console.log(`   ${error.test}: ${error.error}`);
      });
    }
  }
}

// Test utilities
const assert = {
  exists: async (filePath) => {
    try {
      await fs.access(filePath);
    } catch {
      throw new Error(`File does not exist: ${filePath}`);
    }
  },
  
  isArray: (value, message = 'Value is not an array') => {
    if (!Array.isArray(value)) {
      throw new Error(message);
    }
  },
  
  greaterThan: (actual, expected, message = `Expected ${actual} > ${expected}`) => {
    if (actual <= expected) {
      throw new Error(message);
    }
  },
  
  hasProperty: (obj, prop, message = `Object missing property: ${prop}`) => {
    if (!(prop in obj)) {
      throw new Error(message);
    }
  },
  
  equals: (actual, expected, message = `Expected ${expected}, got ${actual}`) => {
    if (actual !== expected) {
      throw new Error(message);
    }
  }
};

// Main test suite
async function createTestSuite() {
  const runner = new TestRunner();

  // Test 1: Verify data directory structure
  runner.addTest('Data directory structure', async () => {
    await assert.exists('./data');
    await assert.exists('./data/posts.json');
    await assert.exists('./data/summary.json');
  });

  // Test 2: Validate posts.json format
  runner.addTest('Posts JSON validation', async () => {
    const postsData = await fs.readFile('./data/posts.json', 'utf8');
    const posts = JSON.parse(postsData);
    
    assert.isArray(posts, 'posts.json should contain an array');
    
    if (posts.length > 0) {
      const post = posts[0];
      ['title', 'link', 'publishedTime', 'sourceCategory'].forEach(prop => {
        assert.hasProperty(post, prop);
      });
    }
  });

  // Test 3: Validate summary.json format
  runner.addTest('Summary JSON validation', async () => {
    const summaryData = await fs.readFile('./data/summary.json', 'utf8');
    const summary = JSON.parse(summaryData);
    
    ['lastUpdated', 'stats', 'totalPosts', 'categories'].forEach(prop => {
      assert.hasProperty(summary, prop);
    });
    
    assert.isArray(summary.categories, 'Categories should be an array');
  });

  // Test 4: Test RSS processor with limited feeds
  runner.addTest('RSS Processor functionality', async () => {
    const testFeeds = CONFIG.rssFeeds.slice(0, TEST_CONFIG.maxTestFeeds);
    const processor = new RSSProcessor();
    
    // Mock the RSS feeds for testing
    const originalFeeds = CONFIG.rssFeeds;
    CONFIG.rssFeeds = testFeeds;
    
    try {
      const posts = await processor.processAllFeeds();
      assert.isArray(posts, 'processAllFeeds should return an array');
      
      // Restore original configuration
      CONFIG.rssFeeds = originalFeeds;
    } catch (error) {
      CONFIG.rssFeeds = originalFeeds;
      throw error;
    }
  });

  // Test 5: Security validation
  runner.addTest('Security validation', async () => {
    const postsData = await fs.readFile('./data/posts.json', 'utf8');
    const posts = JSON.parse(postsData);
    
    // Check for potential XSS in titles and descriptions
    posts.forEach((post, index) => {
      if (post.title && /<script|javascript:|on\w+=/i.test(post.title)) {
        throw new Error(`Potential XSS in post ${index} title`);
      }
      
      if (post.description && /<script|javascript:|on\w+=/i.test(post.description)) {
        throw new Error(`Potential XSS in post ${index} description`);
      }
    });
  });

  // Test 6: Performance validation
  runner.addTest('Performance metrics', async () => {
    const summaryData = await fs.readFile('./data/summary.json', 'utf8');
    const summary = JSON.parse(summaryData);
    
    if (summary.stats && summary.stats.processingTime) {
      // Processing should complete within reasonable time (5 minutes)
      const maxProcessingTime = 5 * 60 * 1000; // 5 minutes in ms
      if (summary.stats.processingTime > maxProcessingTime) {
        throw new Error(`Processing time too long: ${summary.stats.processingTime}ms`);
      }
    }
  });

  // Test 7: CVE extraction validation
  runner.addTest('CVE extraction', async () => {
    const processor = new RSSProcessor();
    
    // Test CVE extraction with sample data
    const testPost = {
      title: 'CVE-2023-12345 vulnerability analysis',
      description: 'Analysis of CVE-2024-67890 and its impact',
      category: 'Security',
      url: 'test'
    };
    
    const mockFeedConfig = { category: 'Test', priority: 1, url: 'test' };
    const processed = processor.processPost(testPost, mockFeedConfig);
    
    if (processed && processed.cveIds) {
      assert.greaterThan(processed.cveIds.length, 0, 'Should extract CVE IDs');
    }
  });

  return runner;
}

// Main execution
async function main() {
  try {
    const runner = await createTestSuite();
    const success = await runner.runAll();
    
    if (!success) {
      console.log('\n❌ Some tests failed!');
      process.exit(1);
    }
    
    console.log('\n✅ All tests passed!');
    
  } catch (error) {
    console.error('❌ Test runner failed:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { TestRunner, assert };