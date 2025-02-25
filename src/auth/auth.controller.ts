import { Controller, Post, Body, Headers, HttpException, HttpStatus, Get, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';


@Controller('auth')
export class AuthController {
    firebaseAdmin: any;
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    async register(@Body() body: { email: string; password: string; displayName?: string }) {
        try {
            const userRecord = await this.authService.registerUser(body);
            return {
                message: 'User created successfully',
                user: userRecord,
            };
        } catch (error) {
            throw new HttpException(
                error.message || 'Registration failed',
                HttpStatus.BAD_REQUEST
            );
        }
    }

    @Post('login')
    async login(@Body() body: { email: string; password: string }) {
        const { customToken, user } = await this.authService.loginUser(body);
        return {
            message: 'Login successful',
            token: customToken, // カスタムトークンを返す
            user: user // ユーザー情報も合わせて返す
        };
    }

    @Post('logout')
    async logout(@Headers('authorization') token: string) {
        try {
            // Bearer トークンから実際のトークンを取得
            const bearerToken = token?.split(' ')[1];
            if (!bearerToken) {
                throw new HttpException('No token provided', HttpStatus.UNAUTHORIZED);
            }

            await this.authService.logoutUser(bearerToken);
            return {
                message: 'Logout successful'
            };
        } catch (error) {
            throw new HttpException(
                error.message || 'Logout failed',
                HttpStatus.BAD_REQUEST
            );
        }
    }

    // auth.controller.ts に追加
    @Get('user')
    async getUser(@Headers('authorization') authHeader: string) {
        try {
            if (!authHeader) {
                throw new UnauthorizedException('No token provided');
            }

            const bearerToken = authHeader.split(' ')[1];
            if (!bearerToken) {
                throw new UnauthorizedException('Invalid token format');
            }

            const userData = await this.authService.getUserFromToken(bearerToken);
            return { user: userData };
        } catch (error) {
            throw new UnauthorizedException(error.message || 'Invalid token');
        }
    }
}
