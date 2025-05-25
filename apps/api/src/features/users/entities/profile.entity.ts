import { Base } from '@/common/entities';
import { Column, Entity, JoinColumn, OneToOne, Relation } from 'typeorm';
import { User } from './user.entity';

enum Gender {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHER = 'OTHER',
  UNKNOWN = 'UNKNOWN',
}

@Entity()
export class Profile extends Base {
  @OneToOne(() => User, (user) => user.sessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id', referencedColumnName: 'id' })
  user: Relation<User>;

  @Column({ type: 'uuid' })
  user_id: string;

  @Column({ nullable: false })
  name: string;

  @Column({ type: 'enum', enum: Gender, default: Gender.UNKNOWN })
  gender: string;

  @Column({ unique: true, nullable: true })
  phoneNumber?: string;

  @Column({ nullable: true })
  profilePicture?: string;

  @Column({ type: 'timestamp', nullable: true })
  dateOfBirth?: string;

  @Column({ nullable: true, type: 'text' })
  address?: string;
}
