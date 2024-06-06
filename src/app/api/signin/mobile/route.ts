import { NextRequest, NextResponse } from 'next/server';
import { AppxSigninResponse, generateJWT, validateUser } from '@/lib/auth';
import bcrypt from 'bcrypt';
import prisma from '@/db';
import { z } from 'zod';

const requestBodySchema = z.object({
  username: z.string().email(),
  password: z.string(),
});

export async function POST(req: NextRequest) {
  const request = await req.json();
  const { success } = requestBodySchema.safeParse(request);

  if (!success) {
    return NextResponse.json({
      error: 'invalid input',
    });
  }
  try {
    if (process.env.LOCAL_CMS_PROVIDER) {
      return NextResponse.json({
        token: await generateJWT({
          id: '1',
        }),
      });
    }
    const hashedPassword = await bcrypt.hash(request.password, 10);

    const userDb = await prisma.user.findFirst({
      where: {
        email: request.username,
      },
      select: {
        password: true,
        id: true,
        name: true,
      },
    });
    if (
      userDb &&
      userDb.password &&
      (await bcrypt.compare(request.password, userDb.password))
    ) {
      const jwt = await generateJWT({
        id: userDb.id,
      });
      await prisma.user.update({
        where: {
          id: userDb.id,
        },
        data: {
          token: jwt,
        },
      });

      return NextResponse.json({
        token: jwt,
      });
    }
    console.log('not in db');
    const user: AppxSigninResponse = await validateUser(
      request.username,
      request.password,
    );

    const jwt = await generateJWT({
      id: user.data?.userid,
    });

    if (user.data) {
      try {
        await prisma.user.upsert({
          where: {
            id: user.data.userid,
          },
          create: {
            id: user.data.userid,
            name: user.data.name,
            email: request.username,
            token: jwt,
            password: hashedPassword,
          },
          update: {
            id: user.data.userid,
            name: user.data.name,
            email: request.username,
            token: jwt,
            password: hashedPassword,
          },
        });
        return NextResponse.json({
          token: jwt,
        });
      } catch (e) {
        console.log(e);
        return NextResponse.json({
          error: "couldn't authorize",
        });
      }
    }

    return NextResponse.json({
      error: 'user not found',
    });
  } catch (e) {
    console.error(e);
    return NextResponse.json({
      error: 'user not found',
    });
  }
}
