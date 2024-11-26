import { defineConfig } from 'vitest/config'
import { config } from 'dotenv'
//#1
config()

export default defineConfig({
  test: {
    env: process.env,
  }
})
