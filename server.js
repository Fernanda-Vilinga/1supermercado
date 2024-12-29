const fastify = require('fastify')({ logger: true });
const jwt = require('fastify-jwt');

// Configuração do JWT
fastify.register(jwt, { secret: 'supersecret' });

// Rotas aqui...

// Iniciar servidor
const start = async () => {
    try {
        await fastify.listen(3000);
        fastify.log.info(`Servidor rodando em http://localhost:3000`);
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
