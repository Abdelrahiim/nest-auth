import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from './../src/app.module';
import * as pactum from 'pactum';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
    await app.listen(process.env.PORT || 7000);
    pactum.request.setBaseUrl('http://localhost:7000');
  });

  afterAll(() => {
    app.close();
  });

  it('should return "Hello World!"', () => {
    return pactum
      .spec()
      .get('/')
      .expectStatus(200)
      .expectBodyContains('Hello World!');
  });

  it('should return "Hello World!"', () => {
    return pactum
      .spec()
      .get('/')
      .expectStatus(200)
      .expectBodyContains('Hello World');
  });
});
