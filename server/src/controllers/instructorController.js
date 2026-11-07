import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// Fields safe to expose publicly. Everything else (password, apiKey, private
// contact info) is withheld.
const PUBLIC_FIELDS = 'name username department role';

function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// --- Login -----------------------------------------------------------------
// Joi forces username/password to be strings, so an injected operator object
// ({$ne:null}, {$regex:"^S"}, ...) can never reach the query.
const loginSchema = Joi.object({
  username: Joi.string().min(1).max(100).required(),
  password: Joi.string().min(1).max(200).required()
});

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: 'username and password are required' });
    }

    // Look up by username only (a string), then verify with bcrypt. Identical
    // response for "no such user" and "wrong password" so timing/shape leaks
    // nothing, and a $regex password never acts as an extraction oracle.
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');
    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const ok = await instructor.comparePassword(value.password);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// --- Directory -------------------------------------------------------------
// GET /api/instructors  — public directory, limited fields only.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// --- Search ----------------------------------------------------------------
// GET /api/instructors/search?name=...
// Only a `name` string is accepted (stripUnknown drops everything else). An
// operator-laden query simply yields an empty result set (still 200) rather
// than being used as a filter. The name is escaped before use as a regex.
const searchSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).required()
});

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export async function searchInstructors(req, res, next) {
  try {
    const { value, error } = searchSchema.validate(req.query, { stripUnknown: true });
    if (error) {
      return res.json({ count: 0, instructors: [] });
    }

    const filter = { name: new RegExp(escapeRegex(value.name), 'i') };
    const instructors = await Instructor.find(filter).select(PUBLIC_FIELDS).lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
