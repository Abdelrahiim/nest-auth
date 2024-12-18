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
    await app.listen(process.env.PORT || 7000);
    request.setBaseUrl('http://localhost:7000');
  });

  afterAll(() => {
    app.close();
  });

  describe("Authentication", () => {
    const dto = {
      email: "L6k3o@example.com",
      password: "1234568780"
    }

    it("Should Sign Up the User", () => {
      return spec().post("/auth/signup")
        .withBody(dto)
        .expectStatus(201)
        .expectBodyContains(`_id`)
    })

    it("Should Sign In the User", () => {
      return spec().post("/auth/signin")
        .withBody(dto)
        .expectStatus(200)
        .expectBodyContains(`access_token`)
    })
  })
});
