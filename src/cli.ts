#!/usr/bin/env node

import program from 'commander'

import { handleCommand } from './index'
 
program
  .version('0.1.0')
  .option('-k, --keyFile <path>', 'Key file path')
  .parse(process.argv)

handleCommand({
  keyFile: program.keyFile
}).then(result => console.log(result.messageString))
