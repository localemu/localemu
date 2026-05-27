'use strict';

async function handler() {
  return 'Hi LocalEmu';
}

module.exports = {
  createUserHandler: handler,
  authenticateUserHandler: handler
};
