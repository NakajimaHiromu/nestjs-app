import { Injectable, Inject, BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as admin from 'firebase-admin';

@Injectable()
export class AuthService {
    constructor(
        @Inject('FIREBASE_ADMIN') private firebaseAdmin: typeof admin,
    ) { }

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
    async loginUser(data: { email: string; password: string }): Promise<{ customToken: string, user: any }> {
        try {
            const userRecord = await this.firebaseAdmin.auth().getUserByEmail(data.email);
            // カスタムトークンを生成
            const customToken = await this.firebaseAdmin.auth().createCustomToken(userRecord.uid);

            // ユーザー情報も一緒に返す
            return {
                customToken,
                user: {
                    uid: userRecord.uid,
                    email: userRecord.email,
                    displayName: userRecord.displayName || null
                }
            };
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
            // カスタムトークンからIDトークンへの変換が必要
            // カスタムトークンをデコードしてUIDを取得する方法
            const decoded = this.firebaseAdmin.auth().verifySessionCookie(token, true)
                .catch(() => {
                    // セッションクッキー検証に失敗した場合、JWT形式として直接デコード
                    try {
                        // カスタムトークンはJWTなのでデコード可能
                        const parts = token.split('.');
                        if (parts.length !== 3) throw new Error('Invalid token format');

                        const payload = JSON.parse(
                            Buffer.from(parts[1], 'base64').toString()
                        );

                        return { uid: payload.uid || payload.sub };
                    } catch (e) {
                        throw new BadRequestException('Invalid token format');
                    }
                });

            // 取得したUIDを使用してトークンを無効化
            const uid = (await decoded).uid;
            if (uid) {
                await this.firebaseAdmin.auth().revokeRefreshTokens(uid);
            } else {
                throw new BadRequestException('Could not determine user ID from token');
            }
        } catch (error) {
            console.error('Logout error:', error);
            throw new BadRequestException('Invalid token or logout failed');
        }
    }

    /**
     * トークン検証
     * @param token Firebase認証トークン
     * @returns デコードされたトークン
     */
    async validateToken(token: string) {
        try {
            const decodedToken = await this.firebaseAdmin.auth().verifyIdToken(token);
            const userRecord = await this.firebaseAdmin.auth().getUser(decodedToken.uid);

            return {
                uid: userRecord.uid,
                email: userRecord.email,
                displayName: userRecord.displayName
            };
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }
    }

    async getUserFromToken(token: string) {
        try {
            // トークンを検証して、ユーザー情報を取得
            const decodedToken = await this.firebaseAdmin.auth().verifyIdToken(token);
            const userRecord = await this.firebaseAdmin.auth().getUser(decodedToken.uid);

            return {
                uid: userRecord.uid,
                email: userRecord.email,
                displayName: userRecord.displayName || null
            };
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }
    }
}