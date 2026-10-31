
const bcrypt = require('bcryptjs');

if (!process.stdin.isTTY || !process.stdin.setRawMode) {
  console.error('Please run this script in the VS Code terminal.');
  process.exit(1);
}

process.stdout.write('Enter your new PATCHBACK password: ');

let password = '';

process.stdin.setRawMode(true);
process.stdin.setEncoding('utf8');
process.stdin.resume();

process.stdin.on('data', async (key) => {
  if (key === '\u0003') {
    process.stdout.write('\nCancelled.\n');
    process.exit(1);
  }

  if (key === '\r' || key === '\n') {
    process.stdin.setRawMode(false);
    process.stdin.pause();

    if (password.length < 8) {
      console.log('\nUse a password with at least 8 characters. Run the script again.');
      process.exit(1);
    }

    const hash = await bcrypt.hash(password, 12);
    console.log('\n\nYour bcrypt hash is:\n');
    console.log(hash);
    console.log('\nCopy the hash into your private .env file.');
    password = '';
    return;
  }

  if (key === '\u007f' || key === '\b') {
    password = password.slice(0, -1);
    return;
  }

  if (key.length === 1 && key >= ' ') {
    password += key;
  }
});
