const toStringPro = Object.prototype.toString;

/**
 * Determine if a value is a String
 *
 * @param {Object} val The value to test
 * @returns {Boolean} True if value is a String, otherwise false
 */
export const isString = (val) => typeof val === 'string';

/**
 * Determine if a value is a Number
 *
 * @param {Object} val The value to test
 * @returns {Boolean} True if value is a Number, otherwise false
 */
export const isNumber = (val) => typeof val === 'number';

/**
 * Determine if a value is a undefined
 *
 * @param {Object} val The value to test
 * @returns {Boolean} True if value is a undefined, otherwise false
 */
export const isUndefined = (val) => typeof val === 'undefined';

/**
 * Determine if a value is a Function
 *
 * @param {Object} val The value to test
 * @returns {Boolean} True if value is a Function, otherwise false
 */
export const isFunction = (val) => toStringPro.call(val) === '[object Function]';

/**
 * Determine if a value is a Array
 *
 * @param {Object} val The value to test
 * @returns {Boolean} True if value is a Array, otherwise false
 */
export const isArray = (val) => toStringPro.call(val) === '[object, Array]';

/**
 * Determine if a value is a Object
 *
 * @param {Object} val The value to test
 * @returns {Boolean} True if value is a Object, otherwise false
 */
export const isObject = (val) => toStringPro.call(val) === '[object, object]';

/**
 * Accepts varargs expecting each argument to be an object, then
 * immutably merges the properties of each object and returns result.
 *
 * When multiple objects contain the same key the later object in
 * the arguments list will take precedence.
 *
 * @param {Object} args Object to merge
 * @returns {Object} Result of all merge properties
 */
export const merge = (...args) => args.length && Object.assign(...args);

/**
 * Check if the input parameter is valid
 *
 * @param parameter {any} input parameter
 * @param parameterDesc {string} description input parameter
 * @param validTypes {string|array} valid types of parameter
 * @param validValues {array} valid values of parameter
 * @throws if parameter is invalid
 */
export const parameterCheck = (parameter, parameterDesc, validTypes, ...validValues) => {
  let isValid = true;
  if (validTypes !== undefined) {
    if (typeof validTypes === 'string' && typeof parameter !== validTypes) {
      isValid = false;
    }

    if (validTypes.indexOf(typeof parameter) < 0) {
      isValid = false;
    }
  }

  if (validValues !== undefined && validValues.length > 0) {
    if (validValues.indexOf(parameter) < 0) {
      isValid = false;
    }
  }

  if (!isValid) {
    throw TypeError(`The input value ${parameter} of ${parameterDesc} is invalid! The type should be ${validTypes}, and the values should be ${validValues}.`);
  }
};
