import { Controller, Post, Body, Headers, HttpException, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';


@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

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
        const token = await this.authService.loginUser(body);
        return {
            message: 'Login successful',
            token: token,
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
}
