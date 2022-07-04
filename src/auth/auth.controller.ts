import { Body, Controller, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { RtGuard } from 'src/common/guards';
import { GetCurrentUser, GetCurrentUserId, Public } from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() body: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(body);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() body: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(body);
  }

  @Post('local/logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }
  
  @Public()
  @UseGuards(RtGuard)
  @Post('local/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@GetCurrentUser('refreshToken') refreshToken: string, @GetCurrentUserId() userId: number) {
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
