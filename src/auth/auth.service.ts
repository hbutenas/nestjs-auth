import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  public async signupLocal(body: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(body.password);

    const newUser = await this.prisma['User'].create({
      data: {
        email: body.email,
        hash,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    this.updateRtHash(newUser.id, tokens.refresh_token);

    return tokens;
  }

  public async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma['User'].findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Invalid email address or password');
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.hash);

    if (!passwordMatches) {
      throw new ForbiddenException('Invalid email address or password');
    }

    const tokens = await this.getTokens(user.id, user.email);
    this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  public async logout(userId: number) {
    await this.prisma['User'].updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  public async refreshTokens(userId: number, rt: string) {
    const user = await this.prisma['User'].findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access denied');
    }

    const rtMatches = await bcrypt.compare(rt, user.hashedRt);

    if (!rtMatches) {
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  // Helpers

  private async hashData(data: string): Promise<string> {
    return bcrypt.hash(data, 10);
  }

  private async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      await this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15, // express in seconds, 1 min * 15 = 15min
        },
      ),
      await this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 24 * 7, // express in seconds, 1min * 1hour * 1day * 7days
        },
      ),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  private async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma['User'].update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }
}
