import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from './../src/app.module';
import { request, spec } from 'pactum';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
    await app.listen(process.env.PORT || 3000);
    request.setBaseUrl('http://localhost:3000');
  });

  afterAll(async () => {
    await app.get('REDIS_CLIENT').quit(); // Close the Redis client since it would not be close with the
    await app.close();
  });

  describe('Authentication', () => {
    const dto = {
      email: 'L6k3o@example.com',
      password: '1234568780',
    };

    it('Should Sign Up the User', () => {
      return spec().post('/users').withBody(dto).expectStatus(201);
      // .expectBodyContains(`_id`);
    });
  });
});
