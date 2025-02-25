import { Global, Module } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Global()
@Module({
    imports: [ConfigModule],
    providers: [
        {
            provide: 'FIREBASE_ADMIN',
            useFactory: async (configService: ConfigService) => {
                const serviceAccount = configService.get('FIREBASE_SERVICE_ACCOUNT');
                if (!serviceAccount) {
                    throw new Error('FIREBASE_SERVICE_ACCOUNT is not defined');
                }
                
                const firebaseAdmin = admin.initializeApp({
                    credential: admin.credential.cert(JSON.parse(serviceAccount)),
                });
                return firebaseAdmin;
            },
            inject: [ConfigService],
        },
    ],
    exports: ['FIREBASE_ADMIN'],
})
export class FirebaseModule {}