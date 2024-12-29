const fastify = require('fastify')({ logger: true });
const jwt = require('fastify-jwt');
const db = require('./firebase');
const bcrypt = require('bcrypt');

// Configurar JWT
fastify.register(jwt, {
  secret: 'Vilinga-key', 
});

// Middleware para verificar JWT
fastify.decorate('authenticate', async (req, reply) => {
  try {
    await req.jwtVerify();
  } catch (err) {
    reply.send(err);
  }
});

// Testar conexão inicial
fastify.get('/', async () => {
  return { message: 'API do supermercado em funcionamento!' };
});

// Rota para registrar o administrador
fastify.post('/auth/registeradmin', async (req, reply) => {
  const { nome, email, senha } = req.body;

  // Verificar se os campos foram preenchidos
  if (!nome || !email || !senha) {
    return reply.status(400).send({ message: 'Preencha todos os campos.' });
  }

  try {
    // Verificar se o administrador já existe
    const userRef = db.collection('usuarios').where('email', '==', email).limit(1);
    const existingUser = await userRef.get();

    if (!existingUser.empty) {
      return reply.status(400).send({ message: 'Usuário já cadastrado.' });
    }

    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(senha, 10);

    // Criar o administrador no Firestore
    const newAdmin = await db.collection('usuarios').add({
      nome,
      email,
      senha: hashedPassword,
      tipo_de_usuario: 'ADMIN',
    });

    return reply.status(201).send({ message: 'Administrador criado com sucesso', id: newAdmin.id });
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao criar administrador' });
  }
});

// Rota de Login
fastify.post('/auth/login', async (req, reply) => {
  const { email, senha } = req.body;

  // Verificar se os campos foram preenchidos
  if (!email || !senha) {
    return reply.status(400).send({ message: 'Preencha todos os campos.' });
  }

  try {
    // Buscar o usuário no Firestore
    const userRef = db.collection('usuarios').where('email', '==', email).limit(1);
    const userSnapshot = await userRef.get();

    if (userSnapshot.empty) {
      return reply.status(400).send({ message: 'Usuário não encontrado.' });
    }

    // Pegar o primeiro usuário encontrado
    const user = userSnapshot.docs[0].data();

    // Verificar se a senha corresponde
    const isPasswordValid = await bcrypt.compare(senha, user.senha);
    if (!isPasswordValid) {
      return reply.status(400).send({ message: 'Senha incorreta.' });
    }

    // Gerar o token JWT
    const token = fastify.jwt.sign({ id: userSnapshot.docs[0].id, tipo_de_usuario: user.tipo_de_usuario });

    return reply.status(200).send({ token });
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao realizar login' });
  }
});

// Rota para criar um novo balconista (somente administrador)
fastify.post('/balconistas', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { nome, email, senha } = req.body;
  const user = req.user; // O usuário autenticado é adicionado ao `req.user`

  // Verificar se o usuário é administrador
  if (user.tipo_de_usuario !== 'ADMIN') {
    return reply.status(403).send({ message: 'Lamentamos. Somente os  administradores podem cadastrar balconistas.' });
  }

  if (!nome || !email || !senha) {
    return reply.status(400).send({ message: 'Preencha todos os campos.' });
  }

  try {
    // Verificar se o balconista já existe
    const userRef = db.collection('usuarios').where('email', '==', email).limit(1);
    const existingUser = await userRef.get();

    if (!existingUser.empty) {
      return reply.status(400).send({ message: 'Balconista já cadastrado.' });
    }

    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(senha, 10);

    // Criar o balconista no Firestore
    const newBalconista = await db.collection('usuarios').add({
      nome,
      email,
      senha: hashedPassword,
      tipo_de_usuario: 'BALCONISTA',
    });

    return reply.status(201).send({ message: 'Balconista criado com sucesso', id: newBalconista.id });
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao criar balconista' });
  }
});


// Rota para registrar vendas (somente balconistas)
fastify.post('/vendas', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { cliente, produtos } = req.body;

  // Validar os campos
  if (!cliente || !produtos || !Array.isArray(produtos) || produtos.length === 0) {
    return reply.status(400).send({ message: 'Preencha todos os campos corretamente. Produtos precisam ser informados.' });
  }

  try {
    // Verificar se o usuário autenticado é um balconista
    const user = req.user;
    if (user.tipo_de_usuario !== 'BALCONISTA') {
      return reply.status(403).send({ message: 'Apenas balconistas podem registrar vendas.' });
    }

    // Calcular o total com base nos preços e quantidades dos produtos
    let total = 0;
    for (const produto of produtos) {
      if (!produto.nome || !produto.preco || !produto.quantidade) {
        return reply.status(400).send({ message: 'Cada produto precisa conter nome, preço e quantidade.' });
      }
      total += produto.preco * produto.quantidade;
    }

    // Criar a venda no Firestore
    const novaVenda = await db.collection('vendas').add({
      cliente,
      produtos,
      total,
      registrado_por: user.id, // ID do balconista que registrou a venda
      data: new Date().toISOString(), // Data e hora do registro
    });

    return reply.status(201).send({ message: 'Venda registrada com sucesso', id: novaVenda.id, total });
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao registrar venda' });
  }
});



// Rota para listar todas as vendas (somente admin)
fastify.get('/vendas', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const user = req.user;

  // Verificar se o usuário é administrador
  if (user.tipo_de_usuario !== 'ADMIN') {
    return reply.status(403).send({ message: 'Lamentamos. Somente administradores podem consultar vendas.' });
  }

  try {
    // Buscar todas as vendas no Firestore
    const vendasSnapshot = await db.collection('vendas').get();
    const vendas = vendasSnapshot.docs.map(doc => doc.data());

    return reply.status(200).send(vendas);
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao listar as vendas' });
  }
});

// Rota para listar todos os balconistas (somente administrador)
fastify.get('/balconistas', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const user = req.user;

  // Verificar se o usuário é administrador
  if (user.tipo_de_usuario !== 'ADMIN') {
    return reply.status(403).send({ message: 'Lamentamos. Somente administradores podem listar balconistas.' });
  }

  try {
    const snapshot = await db.collection('usuarios').where('tipo_de_usuario', '==', 'BALCONISTA').get();

    const balconistas = snapshot.docs.map(doc => ({
      id: doc.id,
      nome: doc.data().nome,
      email: doc.data().email,
    }));

    return reply.status(200).send(balconistas);
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao listar balconistas' });
  }
});

// Rota para excluir um balconista pelo ID (somente administrador)
fastify.delete('/balconistas/:id', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { id } = req.params;
  const user = req.user;

  // Verificar se o usuário é administrador
  if (user.tipo_de_usuario !== 'ADMIN') {
    return reply.status(403).send({ message: 'Lamentamos. Somente administradores podem excluir balconistas.' });
  }

  try {
    // Buscar o balconista no Firestore
    const balconistaRef = db.collection('usuarios').doc(id);
    const balconista = await balconistaRef.get();

    if (!balconista.exists) {
      return reply.status(404).send({ message: 'Balconista não encontrado.' });
    }

    // Deletar o balconista
    await balconistaRef.delete();

    return reply.status(200).send({ message: 'Balconista excluído com sucesso.' });
  } catch (error) {
    console.error(error);
    return reply.status(500).send({ message: 'Erro ao excluir balconista' });
  }
});

// Inicializar servidor
const start = async () => {
  try {
    await fastify.listen({ port: 3001 });
    console.log('Servidor rodando em http://localhost:3001');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
