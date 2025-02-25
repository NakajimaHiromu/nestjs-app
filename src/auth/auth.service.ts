import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import * as admin from 'firebase-admin';

@Injectable()
export class AuthService {
    constructor(
        @Inject('FIREBASE_ADMIN') private firebaseAdmin: typeof admin,
    ) {}

    /**
     * ユーザーアカウント作成
     * @param data ユーザー情報（email, password, displayName）
     * @returns 作成されたユーザーレコード
     */
    async registerUser(data: { email: string; password: string; displayName?: string }): Promise<admin.auth.UserRecord> {
        try {
            const userRecord = await this.firebaseAdmin.auth().createUser({
                email: data.email,
                password: data.password,
                displayName: data.displayName,
            });
            return userRecord;
        } catch (error) {
            throw new BadRequestException(error.message);
        }
    }
    
    /**
     * ユーザーログイン
     * @param data ログイン情報（email, password）
     * @returns Firebase認証トークン
     */
    async loginUser(data: { email: string; password: string }): Promise<string> {
        try {
            const userRecord = await this.firebaseAdmin.auth().getUserByEmail(data.email);
            // Firebase Admin SDKではパスワード認証が直接できないため、
            // カスタムトークンを生成して返す
            const customToken = await this.firebaseAdmin.auth().createCustomToken(userRecord.uid);
            return customToken;
        } catch (error) {
            throw new BadRequestException('Invalid email or password');
        }
    }

    /**
     * ユーザーログアウト
     * @param token Firebase認証トークン
     */
    async logoutUser(token: string): Promise<void> {
        try {
            // トークンを無効化
            const decodedToken = await this.firebaseAdmin.auth().verifyIdToken(token);
            await this.firebaseAdmin.auth().revokeRefreshTokens(decodedToken.uid);
        } catch (error) {
            throw new BadRequestException('Invalid token or logout failed');
        }
    }
}